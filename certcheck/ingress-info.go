package certcheck

type IngressInfo struct {
	Namespace         string
	Ingress           string
	CertManagerCount  int
	CertManagerUsages []CertManagerUsage
	Hosts             []HostInfo
}
