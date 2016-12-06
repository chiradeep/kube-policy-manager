/*
Copyright 2016 Citrix Systems, Inc

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
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	//"k8s.io/kubernetes/vendor/github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	client "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	clientcmd "k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	clientcmdapi "k8s.io/kubernetes/pkg/client/unversioned/clientcmd/api"

	"k8s.io/kubernetes/pkg/client/restclient"
)

var (
	// value overwritten during build. This can be used to resolve issues.
	flags = pflag.NewFlagSet("", pflag.ExitOnError)

	resyncPeriod = flags.Duration("sync-period", 30*time.Second,
		`Relist and confirm cloud resources this often.`)

	watchNamespace = flags.String("watch-namespace", api.NamespaceAll,
		`Namespace to watch for Ingress. Default is to watch all namespaces`)
)

func main() {
	flags.AddGoFlagSet(flag.CommandLine)
	flags.Parse(os.Args)

	flag.CommandLine.Parse([]string{})

	config, err := restclient.InClusterConfig()
	if err != nil {
		//assume kubectl proxy, localhost:8001, no auth
		cluster := clientcmdapi.Cluster{Server: "http://localhost:8001/"}
		directConfig := clientcmd.NewDefaultClientConfig(*clientcmdapi.NewConfig(),
			&clientcmd.ConfigOverrides{ClusterDefaults: cluster})
		config, err = directConfig.ClientConfig()
		if err != nil {
			glog.Fatalf("%v", err)

		}
	}
	kubeClient, err := client.NewForConfig(config)
	if err != nil {
		glog.Fatalf("%v", err)

	}
	nodeName := os.Getenv("NODE_NAME")

	policyCtrller, err := newNetworkPolicyController(kubeClient, nodeName, *watchNamespace, *resyncPeriod)
	if err != nil {
		glog.Fatalf("%v", err)
	}

	go handleSigterm(policyCtrller)

	policyCtrller.Run()

	for {
		glog.Infof("Handled quit, awaiting pod deletion")
		time.Sleep(30 * time.Second)
	}
}

func handleSigterm(npc *networkPolicyController) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	<-signalChan
	glog.Infof("Received SIGTERM, shutting down")

	exitCode := 0
	if err := npc.Stop(); err != nil {
		glog.Infof("Error during shutdown %v", err)
		exitCode = 1
	}

	glog.Infof("Exiting with %v", exitCode)
	os.Exit(exitCode)
}
