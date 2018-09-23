package main

import (
	"fmt"

	"github.com/cakturk/gonetstat"
)

func main() {
	err := gonetstat.NetStat()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
