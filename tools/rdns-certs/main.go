// Command rdns-certs mints the mTLS material for an rdns deployment
// (PRD §8): the internal CA, per-node client certificates, and the exit
// node's server certificate.
//
// Usage:
//
//	rdns-certs ca      [-name rdns-ca] [-out /etc/rdns]
//	rdns-certs client -ca /etc/rdns/ca.crt -cakey /etc/rdns/ca.key -name node-sg -out /etc/rdns/certs
//	rdns-certs server -ca /etc/rdns/ca.crt -cakey /etc/rdns/ca.key -name exit-my -dns exit.my.example -ip 203.0.113.10 -out /etc/rdns/certs
//
// Files produced (all 0600):
//
//	ca:     <out>/ca.crt, <out>/ca.key
//	client: <out>/<name>.crt, <out>/<name>.key
//	server: <out>/<name>.crt, <out>/<name>.key
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"rdns/internal/certstore"
)

const (
	defaultCATTL    = 10 * 365 * 24 * time.Hour
	defaultLeafTTL  = 365 * 24 * time.Hour
	defaultCAName   = "rdns-ca"
	defaultCAOut    = "/etc/rdns"
	defaultCertsOut = "/etc/rdns/certs"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = cmdCA(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "-h", "--help", "-help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "rdns-certs: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rdns-certs:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `rdns-certs — mint rdns mTLS material

Usage:
  rdns-certs ca      [-name rdns-ca] [-out DIR] [-ttl 87600h]
  rdns-certs client -ca CA.crt -cakey CA.key -name NODE -out DIR [-ttl 8760h]
  rdns-certs server -ca CA.crt -cakey CA.key -name NODE -out DIR -dns HOST[,HOST] [-ip IP] [-ttl 8760h]
  rdns-certs token  -ca CA.crt -cakey CA.key -profile PROF -server HOST:PORT [-dns HOST:PORT] [-ttl 8760h]
`)
}

func cmdCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	name := fs.String("name", defaultCAName, "CA common name")
	out := fs.String("out", defaultCAOut, "output directory")
	ttl := fs.Duration("ttl", defaultCATTL, "CA validity")
	fs.Parse(args)

	ca, err := certstore.NewCA(*name, *ttl)
	if err != nil {
		return err
	}
	caKeyPEM, err := certstore.CAKeyPEM(ca)
	if err != nil {
		return err
	}
	if err := certstore.WritePEM(*out+"/ca.crt", ca.PEM()); err != nil {
		return err
	}
	if err := certstore.WritePEM(*out+"/ca.key", caKeyPEM); err != nil {
		return err
	}
	fmt.Printf("CA %q written to %s/ca.{crt,key} (valid %s)\n", *name, *out, *ttl)
	return nil
}

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	caPath := fs.String("ca", defaultCAOut+"/ca.crt", "CA certificate")
	caKey := fs.String("cakey", defaultCAOut+"/ca.key", "CA private key")
	name := fs.String("name", "", "node name (e.g. node-sg)")
	out := fs.String("out", defaultCertsOut, "output directory")
	ttl := fs.Duration("ttl", defaultLeafTTL, "cert validity")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	ca, err := certstore.LoadSigner(*caPath, *caKey)
	if err != nil {
		return err
	}
	c, err := ca.SignClient(*name, *ttl)
	if err != nil {
		return err
	}
	return writeLeaf(*out, *name, c)
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	caPath := fs.String("ca", defaultCAOut+"/ca.crt", "CA certificate")
	caKey := fs.String("cakey", defaultCAOut+"/ca.key", "CA private key")
	name := fs.String("name", "", "exit node name (e.g. exit-my)")
	out := fs.String("out", defaultCertsOut, "output directory")
	dns := fs.String("dns", "", "comma-separated DNS SANs")
	ips := fs.String("ip", "", "comma-separated IP SANs")
	ttl := fs.Duration("ttl", defaultLeafTTL, "cert validity")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("-name is required")
	}

	var dnsNames []string
	if *dns != "" {
		for _, d := range strings.Split(*dns, ",") {
			if d = strings.TrimSpace(d); d != "" {
				dnsNames = append(dnsNames, d)
			}
		}
	}
	var ipSANs []net.IP
	if *ips != "" {
		for _, ip := range strings.Split(*ips, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				p := net.ParseIP(ip)
				if p == nil {
					return fmt.Errorf("bad -ip %q", ip)
				}
				ipSANs = append(ipSANs, p)
			}
		}
	}
	if len(dnsNames) == 0 && len(ipSANs) == 0 {
		return fmt.Errorf("server cert needs at least one of -dns / -ip")
	}
	ca, err := certstore.LoadSigner(*caPath, *caKey)
	if err != nil {
		return err
	}
	c, err := ca.SignServer(*name, *ttl, dnsNames, ipSANs)
	if err != nil {
		return err
	}
	return writeLeaf(*out, *name, c)
}

func writeLeaf(out, name string, c *certstore.Cert) error {
	crt := out + "/" + name + ".crt"
	key := out + "/" + name + ".key"
	if err := certstore.WritePEM(crt, certstore.CertPEM(c.DER)); err != nil {
		return err
	}
	if err := certstore.WritePEM(key, c.KeyPEM); err != nil {
		return err
	}
	fmt.Printf("cert %q written to %s/%s.{crt,key}\n", name, out, name)
	return nil
}

type PairingPayload struct {
	Version     int    `json:"version"`
	ProfileName string `json:"profile_name"`
	ServerAddr  string `json:"server_addr"`
	ServerName  string `json:"server_name"`
	DNSUpstream string `json:"dns_upstream"`
	CACert      string `json:"ca_cert"`
	ClientCert  string `json:"client_cert"`
	ClientKey   string `json:"client_key"`
	ExpiresAt   int64  `json:"expires_at"`
	ClientIP    string `json:"client_ip,omitempty"`
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	caPath := fs.String("ca", defaultCAOut+"/ca.crt", "CA certificate")
	caKey := fs.String("cakey", defaultCAOut+"/ca.key", "CA private key")
	profile := fs.String("profile", "", "profile name (e.g. my, id, sg)")
	server := fs.String("server", "", "exit node tunnel endpoint host:port (e.g. exit.my:443 or natvps.example:24443)")
	serverName := fs.String("server-name", "", "TLS server_name on server (defaults to server host)")
	dns := fs.String("dns", "", "exit node DNS endpoint host:port (e.g. exit.my:53 or natvps.example:10053)")
	clientIP := fs.String("ip", "", "optional client IP to record")
	ttl := fs.Duration("ttl", defaultLeafTTL, "cert validity duration")
	fs.Parse(args)

	if *profile == "" {
		return fmt.Errorf("-profile is required (e.g. -profile my)")
	}
	if *server == "" {
		return fmt.Errorf("-server is required (host:port)")
	}

	host, _, err := net.SplitHostPort(*server)
	if err != nil {
		host = *server
	}
	if *serverName == "" {
		*serverName = host
	}
	if *dns == "" {
		*dns = net.JoinHostPort(host, "53")
	}

	ca, err := certstore.LoadSigner(*caPath, *caKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	clientNodeName := "node-" + strings.ToLower(*profile)
	cert, err := ca.SignClient(clientNodeName, *ttl)
	if err != nil {
		return fmt.Errorf("sign client: %w", err)
	}

	caData, err := os.ReadFile(*caPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}

	expiresAt := time.Now().Add(*ttl).Unix()
	payload := PairingPayload{
		Version:     1,
		ProfileName: strings.ToLower(*profile),
		ServerAddr:  *server,
		ServerName:  *serverName,
		DNSUpstream: *dns,
		CACert:      string(caData),
		ClientCert:  string(certstore.CertPEM(cert.DER)),
		ClientKey:   string(cert.KeyPEM),
		ExpiresAt:   expiresAt,
		ClientIP:    *clientIP,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	token := "rdns://" + base64.StdEncoding.EncodeToString(jsonBytes)
	fmt.Println(token)
	return nil
}
