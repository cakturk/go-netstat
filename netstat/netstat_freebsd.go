package netstat

import (
	"fmt"
	"log"
	"unsafe"
)

// Socket states
const (
	Established SkState = 0x01
	SynSent             = 0x02
	SynRecv             = 0x03
	FinWait1            = 0x04
	FinWait2            = 0x05
	TimeWait            = 0x06
	Close               = 0x07
	CloseWait           = 0x08
	LastAck             = 0x09
	Listen              = 0x0a
	Closing             = 0x0b

	InpIPv4      = 0x1
	InpIPv6      = 0x2
	InpIPv6Proto = 0x4
)

var skStates = [...]string{
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"", // CLOSE
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

func osTCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	var s string = "net.inet.tcp.pcblist"
	var retry = 5
	var xig, exig *Xinpgen
	var buf []byte
	for {
		b, err := SysctlByName(s)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		xig = (*Xinpgen)(unsafe.Pointer(&b[0]))
		sizeofXof := unsafe.Sizeof(*xig)
		eoff := uintptr(len(b)) - sizeofXof
		exig = (*Xinpgen)(unsafe.Pointer(&b[eoff]))
		if xig.Len != uint64(sizeofXof) || exig.Len != uint64(sizeofXof) {
			log.Fatal("xinpgen size mismatch")
		}
		fmt.Printf("xig: %v, buflen: %d, eoff: %d\n", xig, len(b), eoff)
		if !(xig.Gen != exig.Gen && retry > 0) {
			buf = b
			break
		}
		retry -= 1
	}
	index := xig.Len
	for {
		xig = (*Xinpgen)(unsafe.Pointer(&buf[index]))
		if uintptr(unsafe.Pointer(xig)) >= uintptr(unsafe.Pointer(exig)) {
			break
		}
		xtp := (*Xtcpcb)(unsafe.Pointer(xig))
		if xtp.Len != uint64(unsafe.Sizeof(*xtp)) {
			log.Fatal("xtp size mismatch!")
		}
		inp := xtp.Inp
		fmt.Printf("Proto: %d, IPv: %d\n", xtp.Socket.Xso_protocol, inp.Vflag)

		switch {
		case inp.Vflag&InpIPv4 != 0:
		case inp.Vflag&InpIPv6 != 0:
		}

		index += xig.Len
	}
	return nil, nil
}

func osTCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return nil, nil
}

func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return nil, nil
}

func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return nil, nil
}
