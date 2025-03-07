package main


//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ip_entry ebpf xdp_firewall.bpf.c
