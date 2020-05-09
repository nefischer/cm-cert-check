package certcheck

type IngressInfo struct {
    Namespace             string
    Ingress               string
    CertManagerUsages     []CertManagerUsage
    CertificateExpiryDate string
    Hosts                 []HostInfo
    CertManagerCount      int
}
