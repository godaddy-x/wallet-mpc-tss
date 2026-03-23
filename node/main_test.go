package main

import (
	"testing"
	"time"

	"github.com/godaddy-x/wallet-mpc-tss/walletapi"
)

func TestRunAllNode(t *testing.T) {
	go func() {
		cliConfig := walletapi.ReadJson("cli_node0.json")
		RunMPCNode(cliConfig)
	}()
	go func() {
		cliConfig := walletapi.ReadJson("cli_node1.json")
		RunMPCNode(cliConfig)
	}()
	go func() {
		cliConfig := walletapi.ReadJson("cli_node2.json")
		RunMPCNode(cliConfig)
	}()
	time.Sleep(2000 * time.Minute)
}
