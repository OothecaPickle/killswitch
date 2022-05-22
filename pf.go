package killswitch

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// CreatePF creates a pf.conf
func (n *Network) CreatePF(leak, local bool) {
	var pass bytes.Buffer
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", time.Now().Format(time.RFC1123Z)))
	n.PFRules.WriteString("# sudo pfctl -Fa -f /tmp/killswitch.pf.conf -e\n")
	n.PFRules.WriteString(fmt.Sprintf("# %s\n", strings.Repeat("-", 62)))

	// create var for interfaces
	for k := range n.UpInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("int_%s = %q\n", k, k))
		pass.WriteString(fmt.Sprintf("pass on $int_%s proto udp from any port 67:68 to any port 67:68\n", k))
		if leak {
			pass.WriteString(fmt.Sprintf("pass on $int_%s inet proto icmp all icmp-type 8 code 0\n", k))
		}
		if local {
			pass.WriteString(fmt.Sprintf("pass from $int_%s:network to $int_%s:network\n", k, k))
		}
		pass.WriteString(fmt.Sprintf("pass on $int_%s proto {tcp, udp} from any to $vpn_ip\n", k))
	}
	// create var for vpn
	for k := range n.P2PInterfaces {
		n.PFRules.WriteString(fmt.Sprintf("vpn_%s = %q\n", k, k))
		pass.WriteString(fmt.Sprintf("pass on $vpn_%s all\n", k))
	}
	// add vpn peer IP
	n.PFRules.WriteString(fmt.Sprintf("vpn_ip = %q\n", n.PeerIP))
	n.PFRules.WriteString("set block-policy drop\n")
	n.PFRules.WriteString("set ruleset-optimization basic\n")
	n.PFRules.WriteString("set skip on lo0\n")
	n.PFRules.WriteString("table <nonprivate> const { 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/3, 96.0.0.0/4, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/8, 169.0.0.0/9, 169.128.0.0/10, 169.192.0.0/11, 169.224.0.0/12, 169.240.0.0/13, 169.248.0.0/14, 169.252.0.0/15, 169.255.0.0/16, 170.0.0.0/7, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 240.0.0.0/5, 248.0.0.0/6, 252.0.0.0/7, 254.0.0.0/8, 255.0.0.0/9, 255.128.0.0/10, 255.192.0.0/11, 255.224.0.0/12, 255.240.0.0/13, 255.248.0.0/14, 255.252.0.0/15, 255.254.0.0/16, 255.255.0.0/17, 255.255.128.0/18, 255.255.192.0/19, 255.255.224.0/20, 255.255.240.0/21, 255.255.248.0/22, 255.255.252.0/23, 255.255.254.0/24, 255.255.255.0/25, 255.255.255.128/26, 255.255.255.192/27, 255.255.255.224/28, 255.255.255.240/29, 255.255.255.248/30, 255.255.255.252/31, 255.255.255.254/32 }\n")
	// n.PFRules.WriteString("block out quick inet6 all\n")
	if leak {
		n.PFRules.WriteString("pass quick proto {tcp, udp} from any to any port 53 keep state\n")
	}
	n.PFRules.WriteString("block inet from <nonprivate> to any\n")
	n.PFRules.WriteString("block inet from any to <nonprivate>\n")
	n.PFRules.WriteString(pass.String())
}
