package certcheck

type CertManagerFilter struct {
	Key          string `yaml: "key"`
	Value        string `yaml: "value"`
	FriendlyName string `yaml: "friendlyName"`
}

type CertManagerUsage struct {
	Name       string
	IsManaging bool
}
