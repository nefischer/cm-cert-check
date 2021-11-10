package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	cmioclientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha3"
	"github.com/sirupsen/logrus"
	networkingv1Beta1 "k8s.io/api/networking/v1beta1"
	"k8s.io/client-go/kubernetes"
	"path/filepath"
	
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IngressCertificateChecker struct {
	Logger                       *logrus.Logger
	KubeClient                   *kubernetes.Clientset
	CmioClient                   *cmioclientset.CertmanagerV1alpha3Client
	CertManagerLabelFilter       []CertManagerFilter
	CertManagerAnnotationsFilter []CertManagerFilter
	IngressInfoChannel           chan IngressInfo
	Ctx							 context.Context
}

func (c *IngressCertificateChecker) GetActiveManagers(filters []CertManagerFilter, metadataMap map[string]string) []CertManagerUsage {
	usages := make([]CertManagerUsage, len(filters))

	for i, filter := range filters {
		isManaging := false
		for key, value := range metadataMap {
			if key == filter.Key && value == filter.Value {
				isManaging = true
			}
		}
		usages[i] = CertManagerUsage{
			Name:       filter.FriendlyName,
			IsManaging: isManaging,
		}
	}

	return usages
}

func (c *IngressCertificateChecker) GetIngressInfos() {
	defer close(c.IngressInfoChannel)

	listOptions := metav1.ListOptions{}
	networkingApi := c.KubeClient.NetworkingV1beta1()
	ingresses, err := networkingApi.Ingresses("").List(c.Ctx, listOptions)

	if err != nil {
		c.Logger.Error("GetIngressInfos", err)
		return
	}

	for _, ingress := range ingresses.Items {
		var hosts []string
		for _, tlsBlock := range ingress.Spec.TLS {
			for _, host := range tlsBlock.Hosts {
				hosts = append(hosts, host)
			}
		}

		allCertManUsages := c.GetActiveManagers(c.CertManagerLabelFilter, ingress.Labels)
		allCertManUsages = append(allCertManUsages, c.GetActiveManagers(c.CertManagerAnnotationsFilter, ingress.Annotations)...)

		certManagerCount := 0
		for _, usage := range allCertManUsages {
			if usage.IsManaging {
				certManagerCount = certManagerCount + 1
			}
		}

		if len(hosts) == 0 && certManagerCount == 0 {
			// no TLS settings; must be an HTTP endpoint
			continue
		}

		hostInfos, err := c.GetHostInfos(ingress, certManagerCount==0)
		if err != nil {
			c.Logger.Error(fmt.Errorf("ingress %s; namespace %s: %s/%v", ingress.Name, ingress.Namespace, "GetHostInfos", err))
		}

		c.IngressInfoChannel <- IngressInfo{
			Ingress:           ingress.Name,
			Namespace:         ingress.Namespace,
			CertManagerUsages: allCertManUsages,
			CertManagerCount:  certManagerCount,
			Hosts:             hostInfos,
		}
	}
}

func (c *IngressCertificateChecker) Run() {
	c.IngressInfoChannel = make(chan IngressInfo)

	go c.GetIngressInfos()

	//formatter := InfoPrettyFormatter{
	formatter := InfoCSVFormatter{
		IngressInfoChannel: c.IngressInfoChannel,
	}
	formatter.Format()
}

func (c *IngressCertificateChecker) GetHostInfos(ingress networkingv1Beta1.Ingress, checkCertResource bool) ([]HostInfo, error) {
	var hostInfos []HostInfo
	var hosts []string

	certs, err := c.GetCerts(ingress, checkCertResource)
	if err != nil {
		return nil, fmt.Errorf("%s %v", "GetCerts", err)
	}

	for _, tlsBlock := range ingress.Spec.TLS {
		for _, host := range tlsBlock.Hosts {
			hosts = append(hosts, host)
		}
	}

	hostInfos = make([]HostInfo, len(hosts))
	for i, host := range hosts {
		hostInfos[i] = HostInfo{
			DNSName:    host,
			ExpiryDate: nil,
			IssuedBy:   "",
		}

		for _, cert := range certs {
			for _, c := range cert.Certificate {
				x509Cert, err := x509.ParseCertificate(c)
				if err != nil {
					return nil, fmt.Errorf("ingress %s; namespace %s: %s %v", ingress.Name, ingress.Namespace, "ParseCertificate", err)
				}
				for _, certDNSName := range x509Cert.DNSNames {
					matched, err := filepath.Match(certDNSName, host)
					if err == nil && matched || certDNSName == host {
						hostInfos[i].ExpiryDate = &x509Cert.NotAfter
						hostInfos[i].IssuedBy = x509Cert.Issuer.CommonName
					}
				}
			}
		}
		if hostInfos[i].ExpiryDate == nil {
			var hostsInCert []string
			for _, cert := range certs {
				for _, c := range cert.Certificate {
					x509Cert, err := x509.ParseCertificate(c)
					if err != nil {
						return nil, fmt.Errorf("%s %v", "ParseCertificate", err)
					}
					for _, certDNSName := range x509Cert.DNSNames {
						hostsInCert = append(hostsInCert, certDNSName)
					}
				}
			}

			c.Logger.Warningf("ingress %s in %s has TLS host %s specified but no matching certificates (hosts in cert: %v)", ingress.Name, ingress.Namespace, host, hostsInCert)
		}
	}

	return hostInfos, nil
}

func (c *IngressCertificateChecker) GetCerts(ingress networkingv1Beta1.Ingress, checkCertResource bool) ([]tls.Certificate, error) {
	var certs []tls.Certificate
	for _, ingressTLS := range ingress.Spec.TLS {
		secretName := ingressTLS.SecretName
		if secretName == "" {
			return nil, fmt.Errorf("secretName is not defined but should be")
		}
		core := c.KubeClient.CoreV1()
		secret, err := core.Secrets(ingress.Namespace).Get(c.Ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		certPEMBlock := secret.Data["tls.crt"]
		cert := decodePem(certPEMBlock)
		certs = append(certs, cert)
	}
	return certs, nil
}
