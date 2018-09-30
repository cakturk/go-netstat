package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cakturk/go-netstat/netstat"
)

var (
	udp       = flag.Bool("udp", false, "display UDP sockets")
	tcp       = flag.Bool("tcp", false, "display TCP sockets")
	listening = flag.Bool("lis", false, "display only listening sockets")
	all       = flag.Bool("all", false, "display both listening and non-listening sockets")
	help      = flag.Bool("help", false, "display this help screen")
)

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}
	fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

	if *udp {
		tabs, err := netstat.UDPSocks(netstat.NoopFilter)
		if err == nil {
			displaySockInfo("udp", tabs)
		}
	} else {
		*tcp = true
	}

	if *tcp {
		var fn netstat.AcceptFn

		switch {
		case *all:
			fn = func(*netstat.SockTabEntry) bool { return true }
		case *listening:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen
			}
		default:
			fn = func(s *netstat.SockTabEntry) bool {
				return s.State != netstat.Listen
			}
		}

		tabs, err := netstat.TCPSocks(fn)
		if err == nil {
			displaySockInfo("tcp", tabs)
		}
	}
}

func displaySockInfo(proto string, s []netstat.SockTabEntry) {
	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		fmt.Printf("%s   %-23s %-23s %-12s %-16s\n", proto, e.LocalAddr, e.RemoteAddr, e.State, p)
	}
}
