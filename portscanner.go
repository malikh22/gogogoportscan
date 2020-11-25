package main

import (
	"fmt"
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


func main() {
	var target string
	var initPort int
	var finalPort int
  validIp := false
	validPorts := false

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
