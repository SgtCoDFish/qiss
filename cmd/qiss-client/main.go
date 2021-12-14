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
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sgtcodfish/qiss"
)

const (
	verbose    = true
	caFileName = "bin/ca.crt"
)

func main() {
	rootCAPEM, err := os.ReadFile(caFileName)
	if err != nil {
		log.Fatalf("failed to read %s: %s", caFileName, err.Error())
		os.Exit(1)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(rootCAPEM); !ok {
		log.Fatalf("failed to append root cert to pool")
		os.Exit(1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: qiss.ServerCertificateValidator(&tls.Config{
				RootCAs: certPool,
			}, verbose),
		},
		Timeout: time.Second * 5,
	}

	resp, err := client.Get("https://localhost:9919/")
	if err != nil {
		log.Fatalf("failed to make request: %s", err.Error())
		os.Exit(1)
	}

	log.Printf("status code: %d", resp.StatusCode)
}
