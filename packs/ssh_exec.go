package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHCreds struct {
	User    string
	KeyPath string
	Port    int
	Pass    string
}

func RunSSH(ip string, creds SSHCreds, command string) (string, error) {
	config, err := sshConfig(creds)
	if err != nil {
		return "", err
	}

	port := creds.Port
	if port == 0 {
		port = 22
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("SSH connect failed to %s: %w", ip, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, ip, config)
	if err != nil {
		return "", fmt.Errorf("SSH handshake failed on %s: %w", ip, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(command); err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("command failed: %w\nstderr: %s", err, stderr.String())
		}
		return "", err
	}

	return stdout.String(), nil
}
func RunSSHScript(ip string, creds SSHCreds, script string) (string, error) {
	return RunSSH(ip, creds, script)
}

func sshConfig(creds SSHCreds) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod

	if creds.Pass != "" {
		auth = append(auth, ssh.Password(creds.Pass))
	}

	if creds.KeyPath != "" {
		key, err := os.ReadFile(creds.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("SSH key not found at %s: %w", creds.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		return nil, fmt.Errorf("no SSH auth: provide --ssh-key or --ssh-pass")
	}

	return &ssh.ClientConfig{
		User:            creds.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}, nil
}
