/*
Copyright 2016 The Kubernetes Authors.

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

package e2e

import (
	"fmt"
	"path"
	"strings"

	"k8s.io/kubernetes/pkg/api"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/chaosmonkey"
	"k8s.io/kubernetes/test/e2e/common"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
)

// TODO(mikedanese): Add setup, validate, and teardown for:
//  - volumes
//  - persistent volumes
var _ = framework.KubeDescribe("Upgrade [Feature:Upgrade]", func() {
	f := framework.NewDefaultFramework("cluster-upgrade")

	framework.KubeDescribe("master upgrade", func() {
		It("should maintain functioning cluster during upgrade [Feature:MasterUpgrade]", func() {
			cm := chaosmonkey.New(func() {
				v, err := realVersion(framework.TestContext.UpgradeTarget)
				framework.ExpectNoError(err)
				framework.ExpectNoError(framework.MasterUpgrade(v))
				framework.ExpectNoError(checkMasterVersion(f.ClientSet, v))
			})
			cm.Register(func(sem *chaosmonkey.Semaphore) {
				// Close over f.
				testServiceRemainsUp(f, sem)
				testSecretsDuringUpgrade(f, sem)
				testConfigMapsDuringUpgrade(f, sem)
				testGuestbookApplicationDuringUpgrade(f, sem)
				testDaemonSetDuringUpgrade(f, sem)
				testJobsDuringUpgrade(f, sem)
			})
			cm.Do()
		})
	})

	framework.KubeDescribe("node upgrade", func() {
		It("should maintain a functioning cluster [Feature:NodeUpgrade]", func() {
			cm := chaosmonkey.New(func() {
				v, err := realVersion(framework.TestContext.UpgradeTarget)
				framework.ExpectNoError(err)
				framework.ExpectNoError(framework.NodeUpgrade(f, v, framework.TestContext.UpgradeImage))
				framework.ExpectNoError(checkNodesVersions(f.ClientSet, v))
			})
			cm.Register(func(sem *chaosmonkey.Semaphore) {
				// Close over f.
				testServiceUpBeforeAndAfter(f, sem)
				testSecretsBeforeAndAfterUpgrade(f, sem)
				testConfigMapsBeforeAndAfterUpgrade(f, sem)
				testGuestbookApplicationBeforeAndAfterUpgrade(f, sem)
				testDaemonSetBeforeAndAfterUpgrade(f, sem)
				testJobsBeforeAndAfterUpgrade(f, sem)
			})
			cm.Do()
		})

		It("should maintain functioning cluster during upgrade [Feature:ExperimentalNodeUpgrade]", func() {
			cm := chaosmonkey.New(func() {
				v, err := realVersion(framework.TestContext.UpgradeTarget)
				framework.ExpectNoError(err)
				framework.ExpectNoError(framework.NodeUpgrade(f, v, framework.TestContext.UpgradeImage))
				framework.ExpectNoError(checkNodesVersions(f.ClientSet, v))
			})
			cm.Register(func(sem *chaosmonkey.Semaphore) {
				// Close over f.
				testServiceRemainsUp(f, sem)
				testSecretsDuringUpgrade(f, sem)
				testConfigMapsDuringUpgrade(f, sem)
				testGuestbookApplicationDuringUpgrade(f, sem)
				testDaemonSetDuringUpgrade(f, sem)
				testJobsDuringUpgrade(f, sem)
			})
			cm.Do()
		})
	})

	framework.KubeDescribe("cluster upgrade", func() {
		It("should maintain a functioning cluster [Feature:ClusterUpgrade]", func() {
			cm := chaosmonkey.New(func() {
				v, err := realVersion(framework.TestContext.UpgradeTarget)
				framework.ExpectNoError(err)
				framework.ExpectNoError(framework.MasterUpgrade(v))
				framework.ExpectNoError(checkMasterVersion(f.ClientSet, v))
				framework.ExpectNoError(framework.NodeUpgrade(f, v, framework.TestContext.UpgradeImage))
				framework.ExpectNoError(checkNodesVersions(f.ClientSet, v))
			})
			cm.Register(func(sem *chaosmonkey.Semaphore) {
				// Close over f.
				testServiceUpBeforeAndAfter(f, sem)
				testSecretsBeforeAndAfterUpgrade(f, sem)
				testConfigMapsBeforeAndAfterUpgrade(f, sem)
				testGuestbookApplicationBeforeAndAfterUpgrade(f, sem)
				testDaemonSetBeforeAndAfterUpgrade(f, sem)
				testJobsBeforeAndAfterUpgrade(f, sem)
			})
			cm.Do()
		})

		It("should maintain functioning cluster during upgrade [Feature:ExperimentalClusterUpgrade]", func() {
			cm := chaosmonkey.New(func() {
				v, err := realVersion(framework.TestContext.UpgradeTarget)
				framework.ExpectNoError(err)
				framework.ExpectNoError(framework.MasterUpgrade(v))
				framework.ExpectNoError(checkMasterVersion(f.ClientSet, v))
				framework.ExpectNoError(framework.NodeUpgrade(f, v, framework.TestContext.UpgradeImage))
				framework.ExpectNoError(checkNodesVersions(f.ClientSet, v))
			})
			cm.Register(func(sem *chaosmonkey.Semaphore) {
				// Close over f.
				testServiceRemainsUp(f, sem)
				testSecretsDuringUpgrade(f, sem)
				testConfigMapsDuringUpgrade(f, sem)
				testGuestbookApplicationDuringUpgrade(f, sem)
				testDaemonSetDuringUpgrade(f, sem)
				testJobsDuringUpgrade(f, sem)
			})
			cm.Do()
		})
	})
})

// realVersion turns a version constant s into a version string deployable on
// GKE.  See hack/get-build.sh for more information.
func realVersion(s string) (string, error) {
	framework.Logf(fmt.Sprintf("Getting real version for %q", s))
	v, _, err := framework.RunCmd(path.Join(framework.TestContext.RepoRoot, "hack/get-build.sh"), "-v", s)
	if err != nil {
		return v, err
	}
	framework.Logf("Version for %q is %q", s, v)
	return strings.TrimPrefix(strings.TrimSpace(v), "v"), nil
}

func testServiceUpBeforeAndAfter(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testService(f, sem, false)
}

func testServiceRemainsUp(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testService(f, sem, true)
}

// testService is a helper for testServiceUpBeforeAndAfter and testServiceRemainsUp with a flag for testDuringDisruption
//
// TODO(ihmccreery) remove this abstraction once testServiceUpBeforeAndAfter is no longer needed, because node upgrades
// maintain a responsive service.
func testService(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	// Setup
	serviceName := "service-test"

	jig := NewServiceTestJig(f.ClientSet, serviceName)
	// nodeIP := pickNodeIP(jig.Client) // for later

	By("creating a TCP service " + serviceName + " with type=LoadBalancer in namespace " + f.Namespace.Name)
	// TODO it's weird that we have to do this and then wait WaitForLoadBalancer which changes
	// tcpService.
	tcpService := jig.CreateTCPServiceOrFail(f.Namespace.Name, func(s *api.Service) {
		s.Spec.Type = api.ServiceTypeLoadBalancer
	})
	tcpService = jig.WaitForLoadBalancerOrFail(f.Namespace.Name, tcpService.Name, loadBalancerCreateTimeoutDefault)
	jig.SanityCheckService(tcpService, api.ServiceTypeLoadBalancer)

	// Get info to hit it with
	tcpIngressIP := getIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0])
	svcPort := int(tcpService.Spec.Ports[0].Port)

	By("creating pod to be part of service " + serviceName)
	// TODO newRCTemplate only allows for the creation of one replica... that probably won't
	// work so well.
	jig.RunOrFail(f.Namespace.Name, nil)

	// Hit it once before considering ourselves ready
	By("hitting the pod through the service's LoadBalancer")
	jig.TestReachableHTTP(tcpIngressIP, svcPort, loadBalancerLagTimeoutDefault)

	sem.Ready()

	if testDuringDisruption {
		// Continuous validation
		wait.Until(func() {
			By("hitting the pod through the service's LoadBalancer")
			jig.TestReachableHTTP(tcpIngressIP, svcPort, framework.Poll)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without checking if service remains up")
		<-sem.StopCh
	}

	// Sanity check and hit it once more
	By("hitting the pod through the service's LoadBalancer")
	jig.TestReachableHTTP(tcpIngressIP, svcPort, loadBalancerLagTimeoutDefault)
	jig.SanityCheckService(tcpService, api.ServiceTypeLoadBalancer)
}

func checkMasterVersion(c clientset.Interface, want string) error {
	framework.Logf("Checking master version")
	v, err := c.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("checkMasterVersion() couldn't get the master version: %v", err)
	}
	// We do prefix trimming and then matching because:
	// want looks like:  0.19.3-815-g50e67d4
	// got  looks like: v0.19.3-815-g50e67d4034e858-dirty
	got := strings.TrimPrefix(v.GitVersion, "v")
	if !strings.HasPrefix(got, want) {
		return fmt.Errorf("master had kube-apiserver version %s which does not start with %s",
			got, want)
	}
	framework.Logf("Master is at version %s", want)
	return nil
}

func checkNodesVersions(cs clientset.Interface, want string) error {
	l := framework.GetReadySchedulableNodesOrDie(cs)
	for _, n := range l.Items {
		// We do prefix trimming and then matching because:
		// want   looks like:  0.19.3-815-g50e67d4
		// kv/kvp look  like: v0.19.3-815-g50e67d4034e858-dirty
		kv, kpv := strings.TrimPrefix(n.Status.NodeInfo.KubeletVersion, "v"),
			strings.TrimPrefix(n.Status.NodeInfo.KubeProxyVersion, "v")
		if !strings.HasPrefix(kv, want) {
			return fmt.Errorf("node %s had kubelet version %s which does not start with %s",
				n.ObjectMeta.Name, kv, want)
		}
		if !strings.HasPrefix(kpv, want) {
			return fmt.Errorf("node %s had kube-proxy version %s which does not start with %s",
				n.ObjectMeta.Name, kpv, want)
		}
	}
	return nil
}

func testSecretsBeforeAndAfterUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testSecrets(f, sem, false)
}

func testSecretsDuringUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testSecrets(f, sem, true)
}

func testSecrets(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	// Setup
	pod, expectedOutput := common.DoSecretE2EMultipleVolumesSetup(f)

	// Validate
	By("consume secret before upgrade")
	common.DoSecretE2EMultipleVolumesValidate(f, pod, expectedOutput)

	sem.Ready()

	if testDuringDisruption {
		// Continuously validate
		wait.Until(func() {
			By("consume secret during upgrade")
			common.DoSecretE2EMultipleVolumesValidate(f, pod, expectedOutput)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without consuming secrets")
		<-sem.StopCh
	}

	// Validate after upgrade
	By("consume secret after upgrade")
	common.DoSecretE2EMultipleVolumesValidate(f, pod, expectedOutput)

	// Teardown
}

func testConfigMapsBeforeAndAfterUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testConfigMaps(f, sem, false)
}

func testConfigMapsDuringUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testConfigMaps(f, sem, true)
}

func testConfigMaps(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	// Setup
	pod, expectedOutput := common.DoConfigMapE2EWithoutMappingsSetup(f, 0, 0, nil)

	// Validate
	By("consume config-maps before upgrade")
	common.DoConfigMapE2EWithoutMappingsValidate(f, pod, expectedOutput)

	sem.Ready()

	if testDuringDisruption {
		// Continuously validate
		wait.Until(func() {
			By("consume config-maps during upgrade")
			common.DoConfigMapE2EWithoutMappingsValidate(f, pod, expectedOutput)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without consuming config-maps")
		<-sem.StopCh
	}

	// Validate after upgrade
	By("consume config-maps after upgrade")
	common.DoConfigMapE2EWithoutMappingsValidate(f, pod, expectedOutput)

	// Teardown
}

func testGuestbookApplicationBeforeAndAfterUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testGuestbookApplication(f, sem, false)
}

func testGuestbookApplicationDuringUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testGuestbookApplication(f, sem, true)
}

func testGuestbookApplication(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	// Setup
	By("setup guestbook app")
	GuestbookApplicationSetup(f.ClientSet, f.Namespace.Name)

	// Validate
	By("validate guestbook app before upgrade")
	GuestbookApplicationValidate(f.ClientSet, f.Namespace.Name)

	sem.Ready()

	if testDuringDisruption {
		// Continuously validate
		wait.Until(func() {
			By("validate guestbook app during upgrade")
			GuestbookApplicationValidate(f.ClientSet, f.Namespace.Name)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without validating guestbook app")
		<-sem.StopCh
	}

	// Validate after upgrade
	By("validate guestbook app after upgrade")
	GuestbookApplicationValidate(f.ClientSet, f.Namespace.Name)

	// Teardown
	By("teardown guestbook app")
	GuestbookApplicationTeardown(f.ClientSet, f.Namespace.Name)
}

func testDaemonSetBeforeAndAfterUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testDaemonSet(f, sem, false)
}

func testDaemonSetDuringUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testDaemonSet(f, sem, true)
}

func testDaemonSet(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	image := "gcr.io/google_containers/serve_hostname:v1.4"
	dsName := "daemon-set"
	// Setup
	By("setup daemonset")
	complexLabel, nodeSelector := TestDaemonSetWithNodeAffinitySetup(f, dsName, image)

	// Validate
	By("validate daemonset before upgrade")
	TestDaemonSetWithNodeAffinityValidate(f, dsName, complexLabel, nodeSelector)

	sem.Ready()

	if testDuringDisruption {
		// Continuously validate
		wait.Until(func() {
			By("validate daemonset during upgrade")
			TestDaemonSetWithNodeAffinityValidate(f, dsName, complexLabel, nodeSelector)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without validating daemonset")
		<-sem.StopCh
	}

	// Validate after upgrade
	By("validate daemonset after upgrade")
	TestDaemonSetWithNodeAffinityValidate(f, dsName, complexLabel, nodeSelector)

	// Teardown
	By("teardown daemonset")
	TestDaemonSetWithNodeAffinityTeardown(f, dsName)
}

func testJobsBeforeAndAfterUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testJobs(f, sem, false)
}

func testJobsDuringUpgrade(f *framework.Framework, sem *chaosmonkey.Semaphore) {
	testJobs(f, sem, true)
}

func testJobs(f *framework.Framework, sem *chaosmonkey.Semaphore, testDuringDisruption bool) {
	parallelism := int32(2)
	completions := int32(4)

	// Setup
	By("setup job")
	job := TestJobsSetup(f, "randomlySucceedOrFail", "rand-non-local", api.RestartPolicyNever, parallelism, completions)
	// Validate
	By("validate job before upgrade")
	TestJobsValidate(f, job, completions)

	sem.Ready()

	if testDuringDisruption {
		// Continuously validate
		wait.Until(func() {
			By("validate job during upgrade")
			TestJobsValidate(f, job, completions)
		}, framework.Poll, sem.StopCh)
	} else {
		// Block until chaosmonkey is done
		By("waiting for upgrade to finish without validating job")
		<-sem.StopCh
	}

	// Validate after upgrade
	By("validate job after upgrade")
	TestJobsValidate(f, job, completions)

	// Teardown
	TestJobsTeardown(f, job)
}
