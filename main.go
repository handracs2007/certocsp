package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ocsp"
)

func readCertificate(file string) (*x509.Certificate, error) {
	// Read the certificate file content
	fc, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	// Decode the PEM file
	block, _ := pem.Decode(fc)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate data")
	}

	// Parse the certificate data
	return x509.ParseCertificate(block.Bytes)
}

func main() {
	// Parse the certificate data
	cert, err := readCertificate("spring.io.pem")
	if err != nil {
		log.Printf("Failed to read end entity certificate: %s", err)
		return
	}

	// Now read the issuer certificate content.
	issuerCert, err := readCertificate("DigiCert TLS RSA SHA256 2020 CA1.pem")
	if err != nil {
		log.Printf("Failed to read issuer certificate: %s\n", err)
		return
	}

	// Create the OCSP request.
	ocspReq, err := ocsp.CreateRequest(cert, issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		log.Printf("Failed to create OCSP request: %s\n", err)
		return
	}

	// Send the OCSP request.
	ocspURLs := cert.OCSPServer
	for _, ocspURL := range ocspURLs {
		log.Printf("Checking OCSP against %s\n", ocspURL)

		// Build the OCSP request.
		ocspHTTPReq, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(ocspReq))
		if err != nil {
			log.Printf("Failed to build OCSP HTTP request: %s\n", err)
			continue
		}

		// Add the necessary headers.
		ocspHTTPReq.Header.Add("Content-Type", "application/ocsp-request")
		ocspHTTPReq.Header.Add("Accept", "application/ocsp-response")

		// Send the OCSP request.
		ocspHTTPResp, err := http.DefaultClient.Do(ocspHTTPReq)
		if err != nil {
			log.Printf("Failed to send OCSP request: %s\n", err)
			continue
		}
		defer ocspHTTPResp.Body.Close()

		if ocspHTTPResp.StatusCode != http.StatusOK {
			log.Printf("Received HTTP code: %d\n", ocspHTTPResp.StatusCode)
			continue
		}

		// Read the OCSP response.
		ocspResp, err := io.ReadAll(ocspHTTPResp.Body)
		if err != nil {
			log.Printf("Failed to read OCSP response: %s\n", err)
			continue
		}

		// Parse the OCSP response.
		resp, err := ocsp.ParseResponse(ocspResp, issuerCert)
		if err != nil {
			log.Printf("Failed to parse OCSP response: %s\n", err)
			continue
		}

		switch resp.Status {
		case ocsp.Good:
			log.Println("Certificate status: GOOD")

		case ocsp.Revoked:
			log.Println("Certificate status: REVOKED")

		case ocsp.Unknown:
			log.Println("Certificate status: UNKNOWN")
		}

		return
	}
}
