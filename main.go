package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type ip_entry ebpf xdp_firewall.bpf.c

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

  if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}


  if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

  objs := ebpfObjects{}
  if err := loadEbpfObjects(&objs,nil); err != nil{
    log.Fatalf("Error loading obj : %v",err)
  }
  defer objs.Close()
  
  link.AttachXDP(link.XDPOptions{
    Program: objs.FilterXdp,
    Interface: iface.Index,
  })

  
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Welcome to XDP Firewall CLI! Type 'help' for commands.")

	for {
		fmt.Print("> ")
		scanner.Scan()
		command := strings.TrimSpace(scanner.Text())
    fmt.Printf("The command: %s \n",command)
		switch {
		case command == "exit":
			fmt.Println("Bye! 👋")
			return
		case strings.HasPrefix(command, "block "):
			ips := strings.Fields(strings.TrimPrefix(command, "block "))      
      for _,arg := range ips {
        err:= block_ip(arg, &objs)

        if err != nil {
          log.Printf("Error in block: %v \n", err)
        }
                    
      }
		case strings.HasPrefix(command,"unblock"):
      ips := strings.Fields(strings.TrimPrefix(command, "unblock "))
      for _,arg := range ips {
        err := unblock_ip(arg, &objs)

        if err != nil {
          log.Printf("Error in ublock: %v \n", err)         
        }
      }
    case command == "list":
      fmt.Printf("list")
      print_list(&objs)
		case command == "help":
			fmt.Println("Available commands: block <IP>, unblock <IP>, list, exit")
		default:
			fmt.Println("Unknown command. Type 'help' for available commands.")
		}
	}
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}

	ip = ip.To4() // Ensure it's IPv4
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	// Convert to uint32 using Big Endian
	return binary.LittleEndian.Uint32(ip), nil
}

func block_ip(ip string, objs *ebpfObjects ) error{
  u32_ip,err := ipToUint32(ip)
  if err != nil {
    return err
  }
  log.Printf("Blocking ip_str:%s , ip_u32:%d",ip,u32_ip )

  blocker := ebpfIpEntry{Ip: u32_ip,Status: 1}
  err = objs.ebpfMaps.BlockList.Update(u32_ip, blocker, ebpf.UpdateNoExist)
  
  if err != nil {
    return err
  }

  return nil;
}

func unblock_ip(ip string, objs *ebpfObjects ) error{
  u32_ip,err := ipToUint32(ip)
  if err != nil {
    return err
  }
  log.Printf("Unblocking ip_str:%s , ip_u32:%d",ip,u32_ip )

  err = objs.ebpfMaps.BlockList.Delete(u32_ip)
  
  if err != nil {
    return err
  }

  return nil;
}


func print_list(objs *ebpfObjects){
  itr := objs.ebpfMaps.BlockList.Iterate()

  var key uint32
  var value ebpfIpEntry
  fmt.Println("Blocked IPs:")
  
  for itr.Next(key,value ){
    log.Printf("IP: %s",uint32ToIP(value.Ip) )
  }

}

func uint32ToIP(ipUint32 uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip.String()
}
