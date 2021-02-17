package certcheck

import (
	cmioclientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func GetKubeClientSet(kubeconfigPath, kubeContext string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{
			CurrentContext: kubeContext,
		}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func GetCmioClient() (*cmioclientset.CertmanagerV1alpha3Client, error) {
	return nil, nil
}
