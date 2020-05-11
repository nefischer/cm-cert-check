package certcheck

import (
    "fmt"
)

type InfoCSVFormatter struct {
    IngressInfoChannel chan IngressInfo
}

func (f *InfoCSVFormatter) Format() {
    //Namespace             string
    //Ingress               string
    //CertManagerUsages     []CertManagerUsage
    //Hosts                 []HostInfo
    //CertManagerCount      int
    header := "Namespace, Ingress, CertManagerCount"
    headerPrinted := false
    for info := range f.IngressInfoChannel {
        if !headerPrinted {
            for _, usage := range info.CertManagerUsages {
                header = header + ", " + usage.Name
            }
            header = fmt.Sprintf("%s, DNSName, ExpiryDate, IssuedBy", header)
            fmt.Println(header)
            headerPrinted = true
        }
        row := fmt.Sprintf("%s,%s,%d", info.Namespace, info.Ingress, info.CertManagerCount)
        for _, usage := range info.CertManagerUsages {
            row = fmt.Sprintf("%s, %v", row, usage.IsManaging)
        }
        for _, hostInfo := range info.Hosts {
            var expiryDate string
            if hostInfo.ExpiryDate != nil {
                expiryDate = hostInfo.ExpiryDate.Format("2006-01-02")
            } else {
                expiryDate = ""
            }
            
            row = fmt.Sprintf("%s, %s, %s, %s", row, hostInfo.DNSName, expiryDate, hostInfo.IssuedBy)
        }
        fmt.Println(row)
    }
}
