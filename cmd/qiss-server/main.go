/*
Copyright 2021 The cert-manager Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"log"
	"net/http"
	"os"

	"github.com/sgtcodfish/qiss"
)

const (
	verbose    = false
	caFileName = "bin/ca.crt"
)

func main() {
	multiBundle, err := qiss.GenerateMultiKeyRootCert()
	if err != nil {
		log.Printf("unable to generate multi key root cert: %s", err.Error())
		os.Exit(1)
	}

	log.Printf("created root cert with DER len: %d", len(multiBundle.CertDER))

	err = os.WriteFile(caFileName, []byte(multiBundle.CertPEM), 0o664)
	if err != nil {
		log.Printf("unable to write %s", caFileName)
		os.Exit(1)
	}

	log.Printf("wrote CA cert to %s", caFileName)

	csr, keyBundle, err := qiss.GenerateMultiKeyCSR("leafage", []string{"example.com", "localhost"})
	if err != nil {
		log.Printf("unable to generate multi key CSR: %s", err.Error())
		os.Exit(1)
	}

	log.Printf("created CSR with DER len: %d", len(csr))

	issuedCertDER, err := qiss.SignCSR(parsedCSR, multiBundle)
	if err != nil {
		log.Printf("failed to issue cert from CSR: %s", err.Error())
		os.Exit(1)
	}

	log.Printf("successfully issued cert with DER len: %d", len(issuedCertDER))

	certificatePEM := &bytes.Buffer{}
	err = pem.Encode(certificatePEM, &pem.Block{Type: "CERTIFICATE", Bytes: issuedCertDER})
	if err != nil {
		log.Printf("failed to marshal cert as PEM: %s", err.Error())
		os.Exit(1)
	}

	if verbose {
		log.Printf("issued cert PEM:\n%s", certificatePEM)
	}

	legacyKeyPEM, err := keyBundle.LegacyKeyPEM()
	if err != nil {
		log.Printf("failed to marshal legacy private key as PEM: %s", err.Error())
		os.Exit(1)
	}

	serveMux := http.NewServeMux()

	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	tlsCertificate, err := tls.X509KeyPair(certificatePEM.Bytes(), legacyKeyPEM)
	if err != nil {
		log.Printf("failed to load TLS keypair: %s", err.Error())
		os.Exit(1)
	}

	server := &http.Server{
		Addr:    "[::1]:9919",
		Handler: serveMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
		},
	}

	log.Printf("listening on %s", server.Addr)

	err = server.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to listen: %v", err)
	}
}
