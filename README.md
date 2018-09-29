### Usage:

```
Usage of ./go-netstat:
  -all
    	display both listening and non-listening sockets
  -help
    	display this help screen
  -lis
    	display only listening sockets
  -tcp
    	display TCP sockets
  -udp
    	display UDP sockets
```
### Install:

```
$ go install github.com/cakturk/go-netstat
```

### Using as a library
#### Getting the package
```
$ go get github.com/cakturk/go-netstat/netstat
```

```go
import (
	"fmt"

	"github.com/cakturk/go-netstat/netstat"
)

func displaySocks() error {
	// TCP sockets
	socks, err := netstat.UDPSocks()
	if err != nil {
		return err
	}
	for _, e := range socks {
		fmt.Printf("%v\n", e)
	}

	// UDP sockets
	socks, err = netstat.TCPSocks()
	if err != nil {
		return err
	}
	for _, e := range socks {
		fmt.Printf("%v\n", e)
	}
	return nil
}
```
