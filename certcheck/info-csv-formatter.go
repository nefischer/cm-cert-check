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
	
	var footerCount []int
	for info := range f.IngressInfoChannel {
		if !headerPrinted {
			footerCount = make([]int, len(info.CertManagerUsages))
			for _, usage := range info.CertManagerUsages {
				header = header + ", " + usage.Name
			}
			header = fmt.Sprintf("%s, DNSName, ExpiryDate, IssuedBy", header)
			fmt.Println(header)
			headerPrinted = true
		}
		row := fmt.Sprintf("%s,%s,%d", info.Namespace, info.Ingress, info.CertManagerCount)
		for i, usage := range info.CertManagerUsages {
			row = fmt.Sprintf("%s, %v", row, usage.IsManaging)
			if usage.IsManaging {
				footerCount[i] = footerCount[i] + 1
			}
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
	footer := "TOTAL,,"
	for _, count := range footerCount {
		footer = fmt.Sprintf("%s,%d", footer, count)
	}
	fmt.Println(footer)
}
