package collector

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// getK8sConfig returns the K8sConfig object ready to be used
func getK8sConfig(logger log.Logger) (*rest.Config, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		level.Error(logger).Log("msg", "Error getting user home dir", "err", err)
		return nil, err
	}
	kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	level.Info(logger).Log("msg", "Using KubeConfig file at", "path", kubeConfigPath)

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		level.Error(logger).Log("msg", "Error getting kubernetes config", "err", err)
		return nil, err
	}

	return kubeConfig, nil
}

// getK8sClient returns a k8s client based on the kubeconfig file
func getK8sClient(kubeconfig *rest.Config, logger log.Logger) (*kubernetes.Clientset, error) {
	// Creating K8s client connection
	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating K8s client", "err", err)
		return nil, err
	}

	return clientset, nil
}

// getAuthPods returns a list of the running pods in "openshift-authentication"
func getAuthPods(ctx context.Context, client kubernetes.Interface, logger log.Logger) (*v1.PodList, error) {
	pods, err := client.CoreV1().Pods(authenticationNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		level.Error(logger).Log("msg", "Failed to obtain the list of openshift-authentication pods", "err", err)
		return nil, err
	}
	return pods, nil
}

// getPodLogs collects the logs of the pod specified by argument and returns them as string to be parsed later
func getPodLogs(ctx context.Context, client kubernetes.Interface, pod corev1.Pod, logger log.Logger) ([]string, error) {
	podLogOpts := corev1.PodLogOptions{}

	// Getting pod logs
	req := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream(context.TODO())
	if err != nil {
		level.Error(logger).Log("msg", "Error openning the log stream", "err", err)
		return nil, err
	}
	defer podLogs.Close()

	// Converting stream into string
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		level.Error(logger).Log("msg", "Error converting log stream into string", "err", err)
		return nil, err
	}
	logLines := strings.Split(buf.String(), "\n")

	return logLines, nil
}
