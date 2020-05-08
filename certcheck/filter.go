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

func GetCertManagerUsages(filters []CertManagerFilter, metadataMap map[string]string) []CertManagerUsage {
    usages := make([]CertManagerUsage, len(metadataMap))
    
    for i, filter := range filters {
        isUsed := false
        for key, value := range metadataMap {
            if key == filter.Key && value == filter.Value {
                isUsed = true
            }
        }
        usages[i] = CertManagerUsage{
            Name:       filter.FriendlyName,
            IsManaging: isUsed,
        }
    }
    
    return usages
}
