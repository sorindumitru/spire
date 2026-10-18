package k8sclustertrustbundle

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesv1ac "k8s.io/client-go/applyconfigurations/certificates/v1"
	certificatesv1beta1ac "k8s.io/client-go/applyconfigurations/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubernetesClient defines the interface for Kubernetes operations.
type kubernetesClient interface {
	// ApplyClusterTrustBundle creates or updates the ClusterTrustBundle using
	// Server-Side Apply, setting its trust bundle to the provided PEM data.
	ApplyClusterTrustBundle(ctx context.Context, cluster *Cluster, pemData []byte) error
}

// k8sClient implements the kubernetesClient interface.
type k8sClient struct {
	clientset kubernetes.Interface
}

func (c *k8sClient) ApplyClusterTrustBundle(ctx context.Context, cluster *Cluster, pemData []byte) error {
	opts := metav1.ApplyOptions{
		FieldManager: fmt.Sprintf("spire-bundlepublisher-%s", pluginName),
	}

	switch cluster.APIVersion {
	case apiVersionV1:
		spec := certificatesv1ac.ClusterTrustBundleSpec().WithTrustBundle(string(pemData))
		if cluster.SignerName != "" {
			spec.WithSignerName(cluster.SignerName)
		}
		_, err := c.clientset.CertificatesV1().
			ClusterTrustBundles().
			Apply(ctx, certificatesv1ac.ClusterTrustBundle(cluster.ClusterTrustBundleName).WithSpec(spec), opts)
		return err
	case apiVersionV1beta1:
		spec := certificatesv1beta1ac.ClusterTrustBundleSpec().WithTrustBundle(string(pemData))
		if cluster.SignerName != "" {
			spec.WithSignerName(cluster.SignerName)
		}
		_, err := c.clientset.CertificatesV1beta1().
			ClusterTrustBundles().
			Apply(ctx, certificatesv1beta1ac.ClusterTrustBundle(cluster.ClusterTrustBundleName).WithSpec(spec), opts)
		return err
	default:
		return fmt.Errorf("unsupported api version %q", cluster.APIVersion)
	}
}

// newK8sClient creates a new Kubernetes client based on the provided configuration.
func newK8sClient(kubeConfigPath string) (kubernetesClient, error) {
	kubeConfig, err := getKubeConfig(kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error getting kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	return &k8sClient{
		clientset: clientset,
	}, nil
}

// getKubeConfig returns a Kubernetes configuration based on the provided path.
// If the path is empty, it uses the in-cluster configuration.
func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}

	return rest.InClusterConfig()
}
