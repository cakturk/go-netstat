package gonetstat

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	tcpTab = "/proc/net/tcp"
	udpTab = "/proc/net/udp"

	ipv4StrLen = 8
	ipv6StrLen = 32
)

type SockAddr struct {
	IP   net.IP
	Port uint16
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

type SockTabEntry struct {
	InodeNum   uint
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	UID        uint32
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s-1].s
}

var skStates = [...]struct {
	st uint8
	s  string
}{
	{0x01, "ESTABLISHED"},
	{0x02, "SYN_SENT"},
	{0x03, "SYN_RECV"},
	{0x04, "FIN_WAIT1"},
	{0x05, "FIN_WAIT2"},
	{0x06, "TIME_WAIT"},
	{0x07, "CLOSE"},
	{0x08, "CLOSE_WAIT"},
	{0x09, "LAST_ACK"},
	{0x0A, "LISTEN"},
	{0x0B, "CLOSING"},
}

// Errors returned by gonetstat
var (
	ErrNotEnoughFields = errors.New("gonetstat: not enough fields in the line")
)

func parseAddr(s string) (*SockAddr, error) {
	fields := strings.Split(s, ":")
	if len(fields) < 2 {
		return nil, fmt.Errorf("netstat: not enough fields: %v", s)
	}
	v, err := strconv.ParseUint(fields[0], 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip[:], uint32(v))
	v, err = strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return nil, err
	}
	return &SockAddr{IP: ip, Port: uint16(v)}, nil
}

func parseSocktab(r io.Reader) ([]SockTabEntry, error) {
	br := bufio.NewScanner(r)
	tab := make([]SockTabEntry, 0, 4)

	// Discard title
	if br.Scan() {
		_ = br.Text()
	}

	for br.Scan() {
		var e SockTabEntry
		line := br.Text()
		// Skip comments
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 12 {
			return nil, fmt.Errorf("netstat: not enough fields: %v, %v", len(fields), fields)
		}
		addr, err := parseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		e.LocalAddr = addr
		addr, err = parseAddr(fields[2])
		if err != nil {
			return nil, err
		}
		e.RemoteAddr = addr
		u, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, err
		}
		e.State = SkState(u)
		u, err = strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, err
		}
		e.UID = uint32(u)
		u, err = strconv.ParseUint(fields[9], 10, 32)
		if err != nil {
			return nil, err
		}
		e.InodeNum = uint(u)
		tab = append(tab, e)
	}
	return tab, br.Err()
}

func NetStat() error {
	// to change the flags on the default logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	f, err := os.Open(tcpTab)
	if err != nil {
		return err
	}
	tabs, err := parseSocktab(f)
	if err != nil {
		return err
	}
	for _, t := range tabs {
		fmt.Println(t)
	}
	return nil
}
