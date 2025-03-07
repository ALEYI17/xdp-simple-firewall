# **xdp-simple-firewall** 🔥🛡  

A lightweight **XDP-based firewall** using **eBPF** for high-performance packet filtering. This project runs an **eBPF program in the kernel space (C)** and provides a **Go-based user-space CLI** (using **Cilium's eBPF library**) to manage blocked IP addresses.  

## **🚀 Features**  
- Uses **XDP (eXpress Data Path)** for fast packet filtering in the kernel.  
- **CLI-based REPL** for easy firewall management.  
- Allows blocking/unblocking of specific IP addresses.  
- Uses **C for kernel-space eBPF logic** and **Go for user-space control**.  

## **📌 Requirements**  
- Linux with **eBPF support** (kernel `>= 4.18` recommended).  
- **Go** (`>= 1.18`).  
- **clang + llvm** (for compiling eBPF programs).  
- **bpftool** (for debugging).  

## **🔧 Installation**  
1️⃣ **Clone the repository:**  
```sh
git clone https://github.com/ALEYI17/xdp-simple-firewall.git
cd xdp-simple-firewall
```
  
2️⃣ **Build the project:**  
```sh
go build 
```

3️⃣ **Run the firewall (requires sudo):**  
```sh
sudo ./xdp_firewall <interface>
```
  
## **📜 CLI Commands**  
Once the program starts, you can use the following commands:  

| Command                 | Description                                    |
|-------------------------|------------------------------------------------|
| `block <IP>`           | Block all incoming traffic from `<IP>`.        |
| `unblock <IP>`         | Remove `<IP>` from the block list.             |
| `list`                 | Show all currently blocked IPs.                |
| `help`                 | Display available commands.                    |
| `exit`                 | Quit the firewall CLI.                         |

## **🛠 Example Usage**  
```sh
sudo ./xdp_firewall eth0
Welcome to XDP Firewall CLI! Type 'help' for commands.

> block 192.168.1.10
Blocking IP: 192.168.1.10

> list
Blocked IPs:
- 192.168.1.10

> unblock 192.168.1.10
Unblocking IP: 192.168.1.10

> exit
Bye! 👋
```

## **🛡 How It Works**  
1. The **eBPF program** (written in C) runs in **XDP mode**, filtering packets at the **NIC driver level**.  
2. The **Go user-space program** communicates with the eBPF map (via `cilium/ebpf` library) to **add/remove blocked IPs** dynamically.  
3. Blocked IPs are stored in a **BPF hash map**, and packets from those IPs are **dropped instantly**.  

## **🔍 Debugging & Logs**  
You can check active XDP programs using:  
To see logs:  
```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
