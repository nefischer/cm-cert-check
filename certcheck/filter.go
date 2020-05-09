package certcheck

type CertManagerFilter struct {
    Key          string
    Value        string
    FriendlyName string
}

type CertManagerUsage struct {
    Name       string
    IsManaging bool
}

