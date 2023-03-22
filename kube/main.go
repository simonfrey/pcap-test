package main

import (
	"context"
	"fmt"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
)

func main() {
	ctx := context.Background()

	kubeconfig := filepath.Join(
		os.Getenv("HOME"), ".kube", "config",
	)

	// Initialize kubernetes-client
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		fmt.Printf("Error building kubeconfig: %v\n", err)
		os.Exit(1)
	}

	// create new client with the given config
	// https://pkg.go.dev/k8s.io/client-go/kubernetes?tab=doc#NewForConfig
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Printf("Error building kubernetes clientset: %v\n", err)
		os.Exit(2)
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
		replicaSets := map[string]v1.ReplicaSet{}
		replicaSetList, _ := kubeClient.AppsV1().ReplicaSets(namespace.Name).List(ctx, options)
		for _, replicaSet := range (*replicaSetList).Items {
			replicaSets[replicaSet.Name] = replicaSet
		}
		deployments := map[string]v1.Deployment{}
		deploymentsList, _ := kubeClient.AppsV1().Deployments(namespace.Name).List(ctx, options)
		for _, deployment := range (*deploymentsList).Items {
			deployments[deployment.Name] = deployment
		}

		servicesList, _ := kubeClient.CoreV1().Services(namespace.Name).List(ctx, options)
		for _, service := range (*servicesList).Items {
			name := fmt.Sprintf("[SERVICE] %s: %s", service.Name, service.Spec.ClusterIP)
			fmt.Println(name)
			ipMap[service.Spec.ClusterIP] = name
		}

		podList, _ := kubeClient.CoreV1().Pods(namespace.Name).List(ctx, options)

		// List() returns a pointer to slice, derefernce it, before iterating
		for _, podInfo := range (*podList).Items {
			if podInfo.Status.Phase != "Running" {
				continue
			}
			_, exists := ipMap[podInfo.Status.PodIP]
			if exists {
				continue
			}

			name := fmt.Sprintf("[POD] %s", podInfo.Name)
			if len(podInfo.OwnerReferences) > 0 {
				switch podInfo.OwnerReferences[0].Kind {
				case "ReplicaSet":
					// Get replicaset
					replicaSet, ok := replicaSets[podInfo.OwnerReferences[0].Name]
					if ok {
						name = fmt.Sprintf("[REPLICASET] %s", replicaSet.Name)

						if len(replicaSet.OwnerReferences) > 0 &&
							replicaSet.OwnerReferences[0].Kind == "Deployment" {
							deployment, ok := deployments[replicaSet.OwnerReferences[0].Name]
							if ok {
								name = fmt.Sprintf("[DEPLOYMENT] %s", deployment.Name)
							}
						}
					}
				case "Deployment":
					deployment, ok := deployments[podInfo.OwnerReferences[0].Name]
					if ok {
						name = fmt.Sprintf("[DEPLOYMENT] %s", deployment.Name)
					}
				default:
				}
			}

			ipMap[podInfo.Status.PodIP] = name
			fmt.Printf("%s: %s\n", name, podInfo.Status.PodIP)
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
