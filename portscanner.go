//portscanner.go
//A port scanner that conducts a TCP scan given either a valid IPv4
//address or a range using CIDR.
//author: Hera Malik
//version: December 2020

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

//A scan job. Each job has a single target IP.
type ScanJob struct {
	ip   string
}

//the actual port scan. Attempts a TCP connection with the
//target on the given port
func runPortScan(ip string, port int, timeout time.Duration) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			runPortScan(ip, port, timeout)
		}
		//There was a timeout, so this port is likely closed. It is not reported.
		return
	}
	//Closes the connection.
	//The handshake was successful, so the port is reported as open.
	conn.Close()
	fmt.Println(port, "open")
}

//schedules connection attempts
func (job *ScanJob) Start(min, max int, timeout time.Duration) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	//spawns a routine for each port
	for port := min; port <= max; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			runPortScan(job.ip, port, timeout)
		} (port)
	}
}

//checks for the proper form of an IPv4 address
func IsIpv4Net(host string) bool {
   return net.ParseIP(host) != nil
}

//calulates the IP range based on provided CIDR
func CIDRtoIPRange(subnet string) []string {

	//list of host addresses
	var hosts []string

	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Fatal(err)
	}
	//we need the mask and the first IP to get the range
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	firstIP := binary.BigEndian.Uint32(ipv4Net.IP)

	//calculate last IP address using the mask
	lastIP := (firstIP & mask) | (mask ^ 0xffffffff)

	// loop through addresses
	//(subtracting 1 discards the network and broadcast addresses)
	for i := firstIP + 1; i <= lastIP - 1; i++ {
		// convert back to IPv4 addresses
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// returns IP addresses
	return hosts
}

func main() {
	var target string
	var cidr string
	var initPort int
	var finalPort int
	var option string

//flags for testing valid input
	validOption := false
  validIp := false
	validPorts := false


	for validOption != true {
			fmt.Println("Would you like to scan a single target or a subnet? Please answer 1 or 2.")
			fmt.Println("1- Single target scan")
			fmt.Println("2- Range scan")
			fmt.Scanln(&option)
			choice, err := strconv.Atoi(option)
			if err != nil {
				log.Fatal(err)
			}

			if choice == 1 || choice == 2 {
				validOption = true;

				//for a single target scan
				 if choice == 1 {
					//prompts user to enter the target
					for validIp != true {
						fmt.Println("Enter the host you would like to scan: ")
						fmt.Scanln(&target)
						validIp = IsIpv4Net(target)
						if validIp != true {
							fmt.Println("Make sure you enter a valid IPv4 address.")
						}
					}

					//prompts the user for the port range
					for validPorts != true {
						fmt.Println("Enter the port numbers for the start and end of your scan, separated with a space: ")
						fmt.Scanf("%d", &initPort)
						fmt.Scanf("%d", &finalPort)

						//checks if the range is appropriate
						if initPort < 0 || finalPort > 65536 {
							fmt.Println("There was a problem with your selected ports. The lowest port is 0, and the highest is 65536.")
						} else {
							validPorts = true
						}
					}

						fmt.Println("Now running scan on " + target + " for ports " + strconv.Itoa(initPort) + " to " + strconv.Itoa(finalPort))

						//creates the job object
						job := &ScanJob{
						ip:   target,
					}

					//starts the job and times it
					start := time.Now()
					job.Start(initPort, finalPort, 500*time.Millisecond)
					elapsed := time.Since(start)
				  fmt.Printf("Scan completed in %s", elapsed)
				}

				//if the user wants to scan using a CIDR
				if choice == 2 {
					//prompts user to enter the target in CIDR notation
						fmt.Println("Enter the CIDR you would like to scan: ")
						fmt.Scanln(&cidr)

					//prompts the user for the port range
					for validPorts != true {
						fmt.Println("Enter the port numbers for the start and end of your scan, separated with a space: ")
						fmt.Scanf("%d", &initPort)
						fmt.Scanf("%d", &finalPort)

						//checks if the range is appropriate
						if initPort < 0 || finalPort > 65536 {
							fmt.Println("There was a problem with your selected ports. The lowest port is 0, and the highest is 65536.")
						} else {
							validPorts = true
						}
					}

					//converts the CIDR to a range of IP addresses
					jobHosts := CIDRtoIPRange(cidr)
					//iterates through the hosts in the range
					for _, host := range jobHosts {
						fmt.Println("Now running scan on " + host + " for ports " + strconv.Itoa(initPort) + " to " + strconv.Itoa(finalPort))

						//creates the job object
						job := &ScanJob{
						ip:   host,
					}

					//starts the job and times it
					start := time.Now()
					job.Start(initPort, finalPort, 500*time.Millisecond)
					elapsed := time.Since(start)
					fmt.Printf("Scan completed in %s", elapsed)
				}
	  	      }
	      }
       }
}
