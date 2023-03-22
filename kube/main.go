package main

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
)

func main() {
	ctx := context.Background()

	var kubeClient *kubernetes.Clientset
	if kubeconfigPath := os.Getenv("KUBECFG_PATH"); kubeconfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			fmt.Printf("Error building kubeconfig: %v\n", err)
			os.Exit(1)
		}

		kubeClient, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			fmt.Printf("Error building kubernetes clientset: %v\n", err)
			os.Exit(2)
		}
	} else {
		// Load in-cluster config
		config, err := rest.InClusterConfig()
		if err != nil {
			fmt.Printf("Error loading in-cluster config: %v\n", err)
			os.Exit(2)
		}
		// creates the clientset
		kubeClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Printf("Error building kubernetes clientset: %v\n", err)
			os.Exit(2)
		}
	}

	// use the app's label selector name. Remember this should match with
	// the deployment selector's matchLabels. Replace <APPNAME> with the
	// name of your choice
	options := metav1.ListOptions{
		//LabelSelector: "app=<APPNAME>",
	}

	ipMap := map[string]string{}

	// get the pod list
	// https://pkg.go.dev/k8s.io/client-go@v11.0.0+incompatible/kubernetes/typed/core/v1?tab=doc#PodInterface
	namespaceList, _ := kubeClient.CoreV1().Namespaces().List(ctx, options)
	for _, namespace := range (*namespaceList).Items {
		podList, _ := kubeClient.CoreV1().Pods(namespace.Name).List(ctx, options)
		for _, service := range (*podList).Items {
			name := fmt.Sprintf("%s(%s)", service.Name, service.Namespace)

			for _, ip := range service.Status.PodIPs {
				if ip.String() == "None" {
					continue
				}
				for _, containers := range service.Spec.Containers {
					for _, port := range containers.Ports {
						if port.ContainerPort != 0 {
							containerPort := fmt.Sprintf("%s:%d", ip, port.ContainerPort)
							fmt.Println("containerPort", containerPort)
							ipMap[containerPort] = name
						}
						if port.HostPort != 0 {
							hostPort := fmt.Sprintf("%s:%d", ip, port.HostPort)
							fmt.Println("hostPort", hostPort)
							ipMap[hostPort] = name
						}
					}
				}
			}
		}

		servicesList, _ := kubeClient.CoreV1().Services(namespace.Name).List(ctx, options)
		for _, service := range (*servicesList).Items {
			name := fmt.Sprintf("%s(%s)", service.Name, service.Namespace)

			for _, ip := range service.Spec.ClusterIPs {
				if ip == "None" {
					continue
				}
				for _, port := range service.Spec.Ports {
					if port.Port != 0 {
						ipPort := fmt.Sprintf("%s:%d", ip, port.Port)
						fmt.Println("ipPort", ipPort)
						ipMap[ipPort] = name
					}
					if port.NodePort != 0 {
						ipNodePort := fmt.Sprintf("%s:%d", ip, port.NodePort)
						ipMap[ipNodePort] = name
						fmt.Println("ipNodePort", ipNodePort)
					}
				}
			}
		}

	}
	for _, v := range []string{"10.4.21.2", "10.4.11.14"} {
		app, ok := ipMap[v]
		if !ok {
			fmt.Println("NOT FOUND", v)
			continue
		}
		fmt.Println("FOUND", v, app)
	}
}
