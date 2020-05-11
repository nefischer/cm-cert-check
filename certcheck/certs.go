package certcheck

import (
	"crypto/tls"
	"encoding/pem"
	"time"
)

type HostInfo struct {
	DNSName    string
	ExpiryDate *time.Time
	IssuedBy   string
}

func decodePem(certPEMBlock []byte) tls.Certificate {
	var cert tls.Certificate
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}
