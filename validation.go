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

package qiss

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// ServerCertificateValidator returns a tls.Config which validates post-quantum signatures on
// all verified chains (i.e., chains which have had their legacy signatures verified), based on the
// given base config. The returned value is an augmented clone of the base; base is not modified
func ServerCertificateValidator(base *tls.Config, verbose bool) *tls.Config {
	newConfig := base.Clone()
	newConfig.VerifyPeerCertificate = func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, chain := range verifiedChains {
			for i := 0; i < len(chain)-1; i += 1 {
				cert := chain[i]
				issuer := chain[i+1]

				if verbose {
					log.Printf("validating pq signature on <%s> from issuer <%s>", cert.Subject, issuer.Subject)
				}

				_, certPQSignature, err := extractPQExtensionsFromCertificate(cert)
				if err != nil {
					return err
				}

				issuerPQPublicKey, _, err := extractPQExtensionsFromCertificate(issuer)
				if err != nil {
					return err
				}

				if cert.PublicKeyAlgorithm != x509.ECDSA {
					return fmt.Errorf("unsupported legacy public key type")
				}

				legacyPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					return fmt.Errorf("invalid legacy public key")
				}

				derPublicKey, err := x509.MarshalPKIXPublicKey(legacyPublicKey)
				if err != nil {
					return err
				}

				sig := &oqs.Signature{}

				err = sig.Init(signatureAlg, nil)
				if err != nil {
					return err
				}

				// check that the pq signature is of the legacy public key and was made
				// by the issuer
				ok, err = sig.Verify(derPublicKey, certPQSignature, issuerPQPublicKey)
				if err != nil {
					return err
				}

				if !ok {
					return fmt.Errorf("invalid post-quantum signature")
				}

				if verbose {
					log.Printf("successfully validated pq signature on <%s> from issuer <%s>", cert.Subject, issuer.Subject)
				}
			}
		}

		return nil
	}

	return newConfig
}
