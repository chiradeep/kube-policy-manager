# kube-policy-manager

A basic [Network Policy](http://kubernetes.io/docs/user-guide/networkpolicies/) controller for your [Kubernetes](https://kubernetes.io) deployment.

## Description

Enforces ingress network policy using iptables. The controller is run on each Node as a daemonset. 

## Theory of Operation
1. For each selected pod, create a chain in the filter table with a default REJECT policy
2. Create  rules in the FORWARD chain to intercept packets destined to pods selected by network policies. These packets are sent to the chains created in (1)
3. Check the source ip  and destination port of the packet: if it matches the ingress rule selector and destination port, ACCEPT it.

## Requirement

* A running Kubernetes 1.4+ cluster, preferably on AWS. Only tested with the [Kubenet] (http://kubernetes.io/docs/admin/network-plugins/#kubenet) network plugin


## Usage
* Deploy the controller as a daemonset in the `kube-system` namespace

``kubectl --namespace=kube-system create -f  mgr-daemonset.yaml ``

## Building
* `make` to build; `make controller_linux` if you are on Mac/Win to cross compile to linux
* `make container` cross compiles to Linux and builds a container in my namespace. 
* Test locally (e.g., on the Kubernetes API server) by 
  1. running a kubectl proxy : `kubectl proxy --api-prefix=/`
  2. running `sudo NODE_NAME=<some node name> make run`

## TODO
1. Use [IPSet] (http://ipset.netfilter.org/) instead of multiple iptables rules to match source ip of packets
2. Ports in the Ingress policy can be names: handle this (assumes Integer right now)
3. Delete rules that are obsoleted by changes to policies/pods selectively instead of flushing the IPtables chain. This should automatically be the case if IPSets are used
4. According to the NetworkPolicy documentation, ("DefaultDeny: Pods in the namespace will be inaccessible from any source except the pod’s local node.
") ingress rules do not apply to traffic originating from the same host. Not sure why this should be the case. This controller will block traffic even originating on the same host if it does not match any rule.


