package certcheck

import "fmt"

type InfoPrettyFormatter struct {
    IngressInfoChannel chan IngressInfo
}

func (f *InfoPrettyFormatter) Format() {
    for info := range f.IngressInfoChannel {
        fmt.Printf("%+v\n", info)
    }
}
