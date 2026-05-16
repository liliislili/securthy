package main

import (
	"fmt"
	"net"
)

// Device represents one simulated hospital machine
type Device struct {
	IP       string
	Name     string
	Role     string
	Services []Service
}

// Service represents one open port on a device
type Service struct {
	Port    int
	Handler func(net.Conn)
	UDP     bool // true for UDP services (SNMP, DNS)
}

// Start launches all listeners for this device
func (d *Device) Start() error {
	errCh := make(chan error, len(d.Services))

	for _, svc := range d.Services {
		s := svc
		go func() {
			var err error
			if s.UDP {
				err = listenUDP(d.IP, s.Port, s.Handler)
			} else {
				err = listenTCP(d.IP, s.Port, s.Handler)
			}
			if err != nil {
				errCh <- fmt.Errorf("%s:%d — %w", d.IP, s.Port, err)
			}
		}()
	}

	// Collect first error if any
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// listenTCP starts a TCP listener and dispatches connections to the handler
func listenTCP(ip string, port int, handler func(net.Conn)) error {
	addr := fmt.Sprintf("%s:%d", ip, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	fmt.Printf("  [+] TCP %-20s listening\n", addr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handler(conn)
			}()
		}
	}()

	return nil
}

// listenUDP starts a UDP listener (for SNMP etc.)
func listenUDP(ip string, port int, handler func(net.Conn)) error {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}

	fmt.Printf("  [+] UDP %-20s listening\n", addr)

	go func() {
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, remote, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Wrap in a fake conn for the handler
			go handleUDPPacket(conn, remote, buf[:n], port)
		}
	}()

	return nil
}
