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


## Author

[chiradeep](https://github.com/chiradeep)

