/*
Copyright 2016 Citrix Systems

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"

	"encoding/json"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/cache"
	client "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

const (
	podStoreSyncedPollPeriod = 1 * time.Second
)

var (
	keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

// StoreToNetworkPolicyLister makes a Store that lists NetworkPolicy
type StoreToNetworkPolicyLister struct {
	cache.Indexer
}

// networkPolicyController watches the kubernetes api for pod and service changes
// and makes changes to iptables
type networkPolicyController struct {
	client client.Interface

	myNodeName string
	myNodeIP   string

	policyController *cache.Controller
	podController    *cache.Controller
	nsController     *cache.Controller

	podLister    cache.StoreToPodLister
	nsLister     cache.IndexerToNamespaceLister
	policyLister StoreToNetworkPolicyLister

	syncQueue *taskQueue

	iptables utiliptables.Interface

	shutdown bool
	stopCh   chan struct{}
}

// newNetworkPolicyController creates a controller for Kubernetes Network Policies
func newNetworkPolicyController(kubeClient client.Interface, nodeName, namespace string, resyncPeriod time.Duration) (*networkPolicyController, error) {

	npc := networkPolicyController{
		client:     kubeClient,
		stopCh:     make(chan struct{}),
		myNodeName: nodeName,
	}
	npc.iptables = utiliptables.New(utilexec.New(), utildbus.New(), utiliptables.ProtocolIpv4)
	glog.Infof("iptables runner is %v", npc.iptables)
	myNode, err := kubeClient.Core().Nodes().Get(nodeName)

	if err != nil {
		glog.Fatal("Failed to determine my node information") //TODO
	}

	for _, addr := range myNode.Status.Addresses {
		if addr.Type == api.NodeInternalIP {
			npc.myNodeIP = addr.Address
		}
	}
	if npc.myNodeIP == "" {
		glog.Fatal("Failed to determine my node IP")
	}
	glog.Infof("Determined my node IP to be %s", npc.myNodeIP)

	npc.syncQueue = NewTaskQueue(npc.sync)

	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.syncQueue.enqueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			npc.syncQueue.enqueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			if !reflect.DeepEqual(old, cur) {
				npc.syncQueue.enqueue(cur)
			}
		},
	}

	npc.policyLister.Indexer, npc.policyController = cache.NewIndexerInformer(
		cache.NewListWatchFromClient(kubeClient.Extensions().RESTClient(), "networkpolicies", api.NamespaceAll, fields.Everything()),
		&extensions.NetworkPolicy{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	npc.podLister.Indexer, npc.podController = cache.NewIndexerInformer(
		cache.NewListWatchFromClient(kubeClient.Core().RESTClient(), "pods", api.NamespaceAll, fields.Everything()),
		&api.Pod{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	npc.nsLister.Indexer, npc.nsController = cache.NewIndexerInformer(
		cache.NewListWatchFromClient(kubeClient.Core().RESTClient(), "namespaces", api.NamespaceAll, fields.Everything()),
		&api.Namespace{}, resyncPeriod, eventHandler,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	err = npc.establishStatefulFirewall()
	if err != nil {
		glog.Fatal("Failed to set up stateful firewall")
	}

	return &npc, nil
}

func (npc *networkPolicyController) controllersInSync() bool {
	return npc.policyController.HasSynced() &&
		npc.nsController.HasSynced() &&
		npc.podController.HasSynced()
}

func (npc *networkPolicyController) establishStatefulFirewall() error {
	//ensure that connections outgoing from the selected pods can be replied to
	//-I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	comment := "NW Policy requires stateful firewall"
	args := []string{"-m", "comment", "--comment", comment, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
	_, err := npc.iptables.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, "FORWARD", args...)
	return err
}

func (npc *networkPolicyController) getNamespaceNetworkDefaultDenyPolicy(namespace string) (bool, error) {
	namespaceObj, err := npc.nsLister.Get(namespace)
	if err != nil {
		return false, fmt.Errorf("Failed to retrieve namespace object for namespace %s", namespace)
	}
	defaultDenyJson, ok := namespaceObj.ObjectMeta.Annotations["net.beta.kubernetes.io/network-policy"]
	if ok {
		var annot map[string]interface{}
		err := json.Unmarshal([]byte(defaultDenyJson), &annot)
		if err != nil {
			return false, fmt.Errorf("Failed to parse json in namespace annotation")
		}
		ingress, ok := annot["ingress"].(map[string]interface{})
		if !ok {
			return false, fmt.Errorf("Failed to parse json in namespace annotation")
		}
		deny, ok := ingress["isolation"].(string)
		if !ok {
			return false, fmt.Errorf("Failed to parse json in namespace annotation")
		}
		if strings.EqualFold(deny, "DefaultDeny") {
			return true, nil
		} else {
			return false, nil
		}
	}
	return false, nil
}

func (npc *networkPolicyController) createDefaultRejectForPodsInNamespace(namespace string) (map[utiliptables.Chain]bool, error) {

	chains := make(map[utiliptables.Chain]bool)

	var errorEncountered error

	deny, err := npc.getNamespaceNetworkDefaultDenyPolicy(namespace)
	if err != nil {
		glog.Infof("Namespace %s : no network policy default can be determiend", namespace)
		return chains, err
	}
	if !deny {
		glog.Infof("Namespace %s : network policy default is allow", namespace)
		return chains, nil
	}
	glog.Infof("Namespace %s : network policy default is deny", namespace)
	pods, _ := npc.podLister.Pods(namespace).List(labels.Everything())
	for _, pod := range pods {
		if pod.Status.HostIP == npc.myNodeIP {
			glog.Infof("Found pod %s on my host %s", pod.ObjectMeta.Name, npc.myNodeIP)
			//For each destination pod selected by the pod selector that is running on this host, add
			//IPTables rules of the form
			//iptables -A FORWARD -m comment --comment "network policy chain for POD podname " -d <podIP> -j KUBE-NWPLCY-podnamehash
			//The last rule in KUBE-NWPLCY-podnamehash should be a REJECT (or DROP)
			podChain := utiliptables.Chain("KUBE-NWPLCY-" + nameHash(pod.ObjectMeta.Name))
			glog.Infof("Ensuring pod chain %s", string(podChain))
			if pod.Status.PodIP == "" {
				glog.Infof("Pod exists but has no Status.PodIP: %s, skipping chain creation", string(podChain))
				continue
			}
			_, err = npc.iptables.EnsureChain(utiliptables.TableFilter, podChain)
			if err != nil {
				glog.Infof("Error ensuring pod chain %s", string(podChain))
				errorEncountered = fmt.Errorf("Error ensuring policy chain %s", string(podChain))
				continue
			}
			chains[podChain] = true
			comment := "network policy chain for POD " + pod.ObjectMeta.Name
			args := []string{"-m", "comment", "--comment", comment, "-d", pod.Status.PodIP, "-j", string(podChain)}
			_, err = npc.iptables.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, "FORWARD", args...)
			if err != nil {
				glog.Infof("Error ensuring policy rule %v", args)
				errorEncountered = fmt.Errorf("Error ensuring policy rule %v", args)
				continue
			}
			comment = "final rule in network policy chain for POD " + pod.ObjectMeta.Name
			args = []string{"-m", "comment", "--comment", comment, "-j", "REJECT"}
			_, err = npc.iptables.EnsureRule(utiliptables.Append, utiliptables.TableFilter, podChain, args...)
			if err != nil {
				glog.Infof("Error ensuring policy rule %v", args)
				errorEncountered = fmt.Errorf("Error ensuring policy rule %v", args)
				continue
			}
		}
	}

	return chains, errorEncountered
}

func (npc *networkPolicyController) deleteOldChains(newChains map[utiliptables.Chain]bool) error {

	var errorEncountered error

	if iptablesSaveRaw, err := npc.iptables.Save(utiliptables.TableFilter); err != nil {
		glog.Errorf("Failed to execute iptables-save for %s: %v", utiliptables.TableFilter, err)
		errorEncountered = fmt.Errorf("Failed to execute iptables-save for %s: %v", utiliptables.TableFilter, err)
	} else {
		glog.Infof("****Cleaning up old chains################")
		existingChains := utiliptables.GetChainLines(utiliptables.TableFilter, iptablesSaveRaw)
		for chain := range existingChains {
			chainString := string(chain)
			if strings.HasPrefix(chainString, "KUBE-NWPLCY-") {
				_, ok := newChains[chain]
				if !ok {
					glog.Infof("****Cleaning up old chain %s", chainString)
					err = npc.iptables.FlushChain(utiliptables.TableFilter, chain)
					if err != nil {
						glog.Infof("Error flushing policy chain %s", string(chain))
						errorEncountered = fmt.Errorf("Error flushing policy chain %s", string(chain))
					}
					//we need to get the rule in the pod chain that jumps to the chain that needs to be deleted
					readIndex := 0
					for readIndex < len(iptablesSaveRaw) {
						line, n := utiliptables.ReadLine(readIndex, iptablesSaveRaw)
						readIndex = n
						if strings.HasSuffix(line, "-j "+chainString) {
							args := []string{}
							words := strings.Split(line, " ")
							var comment bytes.Buffer
							inComment := false
							for _, w := range words[2:] { //first 2 words are -A CHAIN
								if !inComment {
									args = append(args, w)
								}
								if strings.EqualFold("--comment", w) {
									inComment = true
									continue
								}
								if inComment { //need to put the entire comment in a single array entry
									comment.WriteString(" " + w)
									//find the word ending with ". That marks the end of comment
									if strings.HasSuffix(w, "\"") {
										inComment = false
										//remove quotes and leading spaces
										args = append(args, strings.TrimLeft(strings.Replace(comment.String(), "\"", "", -1), " "))
									}
								}
							}
							origChain := utiliptables.Chain(words[1])

							if err = npc.iptables.DeleteRule(utiliptables.TableFilter, origChain, args...); err != nil {
								glog.Infof("Failed to delete FORWARD rule that jumps to %s", chainString)
								glog.Infof("rule is %v, error is %v", args, err)
								errorEncountered = fmt.Errorf("Failed to delete FORWARD rule that jumps to %s", chainString)
							}

						}
					}
					err = npc.iptables.DeleteChain(utiliptables.TableFilter, chain)
					if err != nil {
						glog.Infof("Error deleting policy chain %s", string(chain))
						errorEncountered = fmt.Errorf("Error deleting policy chain %s error is %v", string(chain), err)
						continue
					}
				}
			}
		}

	}
	return errorEncountered
}

func mergeChains(chains1 map[utiliptables.Chain]bool, chains2 map[utiliptables.Chain]bool) map[utiliptables.Chain]bool {

	for k, v := range chains2 {
		chains1[k] = v
	}
	return chains1
}

func (npc *networkPolicyController) sync(obj interface{}) error {
	if !npc.controllersInSync() {
		time.Sleep(podStoreSyncedPollPeriod)
		return fmt.Errorf("deferring sync till pods controller has synced")
	}

	chains := make(map[utiliptables.Chain]bool)

	var errorEncountered error
	namespaces, err := npc.nsLister.List(labels.Everything())
	if err != nil {
		glog.Infof("Couldn't determine list of namespaces")
		return fmt.Errorf("Couldn't determine list of namespaces")
	}

	for _, namespace := range namespaces {
		newChains, err := npc.createDefaultRejectForPodsInNamespace(namespace.ObjectMeta.Name)
		if err != nil {
			glog.Infof("Namespace %s : could not create default chains for pods in namespace", namespace)
			continue
		}
		mergeChains(chains, newChains)
	}

	policies := npc.policyLister.List()
	glog.Infof("Found %d network policies", len(policies))
	for _, pol := range policies {
		policy := pol.(*extensions.NetworkPolicy)
		//glog.Infof("Policy spec is %v", policy.Spec)
		namespace := policy.ObjectMeta.Namespace //TODO: Can this be empty?
		deny, err := npc.getNamespaceNetworkDefaultDenyPolicy(namespace)
		if err != nil {
			glog.Infof("Namespace %s : no network policy default can be determiend", namespace)
			continue
		}
		if !deny {
			glog.Infof("Namespace %s : network policy default is allow", namespace)
			continue
		}
		glog.Infof("Namespace %s : network policy default is deny, going to find pods in this namespace", namespace)
		selector, _ := unversioned.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		pods, _ := npc.podLister.Pods(namespace).List(selector)
		for _, pod := range pods { //iterate over pods selected by pod selector
			if pod.Status.HostIP == npc.myNodeIP {
				glog.Infof("Found pod %s on my host %s that matches  network policy %s pod selector",
					pod.ObjectMeta.Name, npc.myNodeIP, policy.ObjectMeta.Name)
				//For each destination pod selected by the pod selector that is running on this host, add
				//IPTables rules of the form
				//iptables -A FORWARD -m comment --comment "network policy chain for POD podname " -d <podIP> -j KUBE-NWPLCY-podnamehash
				//For each network policy add a chain for this destination pod (KUBE-NWPLCY-podnamehash-policyhash)
				//iptables -A KUBE-NWPLCY-podnameshash -j KUBE-NWPLCY-podnamehash-policyhash
				//for each peer pod allowed by an ingress rule in this policy
				//iptables -I KUBE-NWPLCY-podnamehash-policyhash -s <peer_pod_IP> --dport <dst port> -j ACCEPT
				//The last rule in KUBE-NWPLCY-podnamehash should be a REJECT (or DROP)
				//iptables -A KUBE-NWPLCY-podnamehash -j REJECT
				//E.g.,
				//-A FORWARD -d 10.244.5.4/32 -m comment --comment "nw policy chain for POD redis-slave-132015689-fksjt" -j KUBE-NWPLCY-7UYHFX
				//-A KUBE-NWPLCY-7UYHFX -m comment --comment "network policy rule for pod redis-slave-132015689-fksjt;policy: guestbook-network-policy" -j KUBE-NWPLCY-7UYHFX-SYJW74
				//-A KUBE-NWPLCY-7UYHFX -m comment --comment "final rule in network policy chain for POD redis-slave-132015689-fksjt" -j REJECT
				//-A KUBE-NWPLCY-7UYHFX-SYJW74 -s 10.244.3.4/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-zir4y" -j ACCEPT
				//-A KUBE-NWPLCY-7UYHFX-SYJW74 -s 10.244.3.3/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-by8e6 -j ACCEPT
				//-A KUBE-NWPLCY-7UYHFX-SYJW74 -s 10.244.3.8/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-p7up8" -j ACCEPT
				podChain := utiliptables.Chain("KUBE-NWPLCY-" + nameHash(pod.ObjectMeta.Name))
				policyChain := utiliptables.Chain("KUBE-NWPLCY-" + nameHash(pod.ObjectMeta.Name) + "-" + nameHash(policy.ObjectMeta.Name+policy.ObjectMeta.Namespace))
				//Pod chain has already been created outside the loop, now create the pod-policy chain
				glog.Infof("Ensuring policy chain %s", string(policyChain))
				_, err = npc.iptables.EnsureChain(utiliptables.TableFilter, policyChain)
				if err != nil {
					glog.Infof("Error ensuring policy chain %s", string(policyChain))
					errorEncountered = fmt.Errorf("Error ensuring policy chain %s", string(policyChain))
					continue
				}
				err = npc.iptables.FlushChain(utiliptables.TableFilter, policyChain) //TODO: do this more selectively
				if err != nil {
					glog.Infof("Error flushing policyChain chain %s", string(policyChain))
					errorEncountered = fmt.Errorf("Error flushing policy chain %s", string(policyChain))
					continue
				}
				chains[policyChain] = true
				comment := "nw policy rule for pod:" + pod.ObjectMeta.Name + ";policy:" + policy.ObjectMeta.Name
				args := []string{"-m", "comment", "--comment", comment, "-j", string(policyChain)}
				_, err = npc.iptables.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, podChain, args...)
				if err != nil {
					glog.Infof("Error ensuring policy rule %v", args)
					errorEncountered = fmt.Errorf("Error ensuring policy rule %v", args)
					continue
				}
				if len(policy.Spec.Ingress) == 0 {
					glog.Infof("No ingress rules for policy %s", policy.ObjectMeta.Name)
				}
				for _, ingress := range policy.Spec.Ingress {
					if len(ingress.From) == 0 {
						//allow everything according to spec
						glog.Infof("No From rules for ingress")
						for _, port := range ingress.Ports {
							intPort := port.Port.String() //TODO: assumes numerical, not named port in policy
							proto := "tcp"
							if port.Protocol != nil {
								proto = strings.ToLower(string(*port.Protocol))
							}
							comment = "allow all src ip: nw policy rule for port: " + intPort
							args = []string{
								"-m", proto,
								"-p", proto,
								"-m", "state",
								"--state", "new",
								"--dport", intPort,
								"-m", "comment",
								"--comment", comment,
								"-j", "ACCEPT"}
							_, err = npc.iptables.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, policyChain, args...)
							if err != nil {
								glog.Infof("Error ensuring policy rule in chain %s:  %v, %v", string(policyChain), args, err)
								errorEncountered = fmt.Errorf("Error ensuring policy rule in chain %s:  %v, %v", string(policyChain), args, err)
								continue
							}
						}
					}
					//TODO: use ipsets to scale this properly
					for _, peer := range ingress.From {
						peerSelector, _ := unversioned.LabelSelectorAsSelector(peer.PodSelector)
						peerPodsAllowed, _ := npc.podLister.List(peerSelector)
						for _, peerPod := range peerPodsAllowed {
							glog.Info("allowed pod is ", peerPod.Status.PodIP)
							if peerPod.Status.PodIP == "" || len(peerPod.Status.PodIP) < 7 {
								continue
							}
							for _, port := range ingress.Ports {
								intPort := port.Port.String() //TODO: assumes numerical, not named port in policy
								proto := "tcp"
								if port.Protocol != nil {
									proto = strings.ToLower(string(*port.Protocol))
								}
								comment = "nw policy rule for peer pod:" + peerPod.ObjectMeta.Name + ", ip:" + peerPod.Status.PodIP
								args = []string{
									"-m", proto,
									"-p", proto,
									"-m", "state",
									"--state", "new",
									"-s", peerPod.Status.PodIP,
									"--dport", intPort,
									"-m", "comment",
									"--comment", comment,
									"-j", "ACCEPT"}
								_, err = npc.iptables.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, policyChain, args...)
								if err != nil {
									glog.Infof("Error ensuring policy rule in chain %s:  %v, %v", string(policyChain), args, err)
									errorEncountered = fmt.Errorf("Error ensuring policy rule in chain %s:  %v, %v", string(policyChain), args, err)
									continue
								}
							}
						}
					}
				}
			}
		}
	}
	errorEncountered = npc.deleteOldChains(chains)

	return errorEncountered
}

// nameHash takes the name of a pod/policy
// returns the associated 6 character hash. This is computed by hashing (sha256)
// then encoding to base32 and truncating to 6 chars. We do this because IPTables
// Chain Names must be <= 28 chars long, and the longer they are the harder they are to read.
func nameHash(name string) string {
	hash := sha256.Sum256([]byte(name))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return encoded[:6]
}

// Stop stops the network policy controller.
func (npc *networkPolicyController) Stop() error {

	// Only try draining the workqueue if we haven't already.
	if !npc.shutdown {
		npc.shutdown = true
		close(npc.stopCh)

		glog.Infof("Shutting down controller queues.")
		npc.syncQueue.shutdown()

		return nil
	}

	return fmt.Errorf("shutdown already in progress")
}

// Run starts the network policy controller.
func (npc *networkPolicyController) Run() {
	glog.Infof("starting network policy controller")

	go npc.policyController.Run(npc.stopCh)
	go npc.podController.Run(npc.stopCh)
	go npc.nsController.Run(npc.stopCh)

	go npc.syncQueue.run(time.Second, npc.stopCh)

	<-npc.stopCh
}
