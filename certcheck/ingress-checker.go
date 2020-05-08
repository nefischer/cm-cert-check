package certcheck

import (
    "github.com/sirupsen/logrus"
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
        
        c.IngressInfoChannel <- IngressInfo{
            Ingress:               ingress.Name,
            Namespace:             ingress.Namespace,
            CertManagerUsages:     allCertManUsages,
            CertificateExpiryDate: "",
            Hosts:                 hosts,
        }
    }
}

func (c *IngressCertificateChecker) Run() {
    c.IngressInfoChannel = make(chan IngressInfo)
    
    go c.GetIngressInfos()
    
    formatter := InfoPrettyFormatter{
       IngressInfoChannel: c.IngressInfoChannel,
    }
    formatter.Format()
}
