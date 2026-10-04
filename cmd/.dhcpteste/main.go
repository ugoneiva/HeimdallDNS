// Cliente DHCP de teste: pede uma concessão na interface e imprime o resultado.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
)

func main() {
	c, err := nclient4.New(os.Args[1])
	if err != nil {
		fmt.Println("erro:", err)
		os.Exit(1)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := c.Request(ctx, dhcpv4.WithOption(dhcpv4.OptHostName(os.Args[2])))
	if err != nil {
		fmt.Println("erro:", err)
		os.Exit(1)
	}
	a := l.ACK
	fmt.Printf("%s %d %s %s %s %s\n", a.YourIPAddr, prefixLen(a), a.Router()[0], a.DNS()[0], a.DomainName(), a.IPAddressLeaseTime(0))
}

func prefixLen(a *dhcpv4.DHCPv4) int { ones, _ := a.SubnetMask().Size(); return ones }
