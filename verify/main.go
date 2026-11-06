//go:build ignore

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"rdns/internal/certstore"
)

// Verifies the exact files in examples/pki/ complete a full mTLS handshake
// the same way rdns-client ⇄ rdns-server will in the field: client dials an
// IP but verifies the cert against server_name "exit-my".
func main() {
	pool, err := certstore.LoadCertPool("examples/pki/ca.crt")
	check("load CA", err)
	serverCert, err := certstore.LoadServerCert("examples/pki/exit-node/exit-my.crt", "examples/pki/exit-node/exit-my.key")
	check("load exit-my cert", err)
	clientCert, err := certstore.LoadServerCert("examples/pki/decision-node/node-sg.crt", "examples/pki/decision-node/node-sg.key")
	check("load node-sg cert", err)

	srvCfg := certstore.ServerTLSConfig(serverCert, pool)
	cliCfg := certstore.ClientTLSConfig(pool, clientCert, "exit-my")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	check("listen", err)
	defer ln.Close()

	type res struct{ peerCN string; err error }
	srvResult := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvResult <- res{"", err}
			return
		}
		tc := tls.Server(c, srvCfg)
		if err := tc.Handshake(); err != nil {
			srvResult <- res{"", err}
			return
		}
		cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName
		srvResult <- res{cn, nil}
	}()

	// Client dials the IP (like <EXIT_IP>:443) but verifies "exit-my".
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		fmt.Println("FAIL client handshake:", err)
		os.Exit(1)
	}
	defer conn.Close()
	r := <-srvResult
	if r.err != nil {
		fmt.Println("FAIL server handshake:", r.err)
		os.Exit(1)
	}
	fmt.Printf("PASS mTLS: client verified cert 'exit-my'; server saw client '%s'\n", r.peerCN)
}

func check(what string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}
