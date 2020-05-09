package certcheck

import (
    "crypto/tls"
    "crypto/x509"
    "github.com/sirupsen/logrus"
    "k8s.io/api/extensions/v1beta1"
    "k8s.io/client-go/kubernetes"
    
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IngressCertificateChecker struct {
    Logger                       *logrus.Logger
    KubeClient                   *kubernetes.Clientset
    CertManagerLabelFilter       []CertManagerFilter
    CertManagerAnnotationsFilter []CertManagerFilter
    IngressInfoChannel           chan IngressInfo
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
    extApi := c.KubeClient.ExtensionsV1beta1()
    ingresses, err := extApi.Ingresses("").List(listOptions)
    
    if err != nil {
        c.Logger.Error(err)
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
        
        certManagerCount :=0
        for _, usage := range allCertManUsages {
            if usage.IsManaging {
                certManagerCount = certManagerCount + 1
            }
        }
        
        hostInfos, err := c.GetHostInfos(ingress)
        if err != nil {
            c.Logger.Error(err)
        }
        
        c.IngressInfoChannel <- IngressInfo{
            Ingress:               ingress.Name,
            Namespace:             ingress.Namespace,
            CertManagerUsages:     allCertManUsages,
            CertManagerCount:      certManagerCount,
            Hosts:                 hostInfos,
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

func (c *IngressCertificateChecker) GetHostInfos(ingress v1beta1.Ingress) ([]HostInfo, error) {
    var hostInfos []HostInfo
    var hosts []string
    
    certs, err := c.GetCerts(ingress)
    if err != nil {
        return nil, err
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
                    return nil, err
                }
                for _, certDNSName := range x509Cert.DNSNames {
                    if certDNSName == host {
                        hostInfos[i].ExpiryDate = &x509Cert.NotAfter
                        hostInfos[i].IssuedBy = x509Cert.Issuer.CommonName
                    }
                }
            }
        }
    }
    
    return hostInfos, nil
}

func (c *IngressCertificateChecker) GetCerts(ingress v1beta1.Ingress) ([]tls.Certificate,error) {
    var certs []tls.Certificate
    for _, ingressTLS := range ingress.Spec.TLS {
        secretName := ingressTLS.SecretName
        core := c.KubeClient.CoreV1()
        secret, err := core.Secrets(ingress.Namespace).Get(secretName, metav1.GetOptions{})
        if err != nil {
            return nil, err
        }
        certPEMBlock := secret.Data["tls.crt"]
        cert := decodePem(certPEMBlock)
        certs = append(certs, cert)
    }
    return certs, nil
}
