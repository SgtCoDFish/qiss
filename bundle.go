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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// MultiKeyCertBundle wraps a certificate along with its keys, both post-quantum and
// legacy.
type MultiKeyCertBundle struct {
	ParsedCert *x509.Certificate

	CertPEM string
	CertDER []byte

	LegacyPublicKey crypto.PublicKey
	PQPublicKey     []byte

	PQKeyBundle
}

// OQSSignature returns a OQS signature object which can be used for signing, based on the
// key embedded in the bundle.
func (m *MultiKeyCertBundle) OQSSignature() (*oqs.Signature, error) {
	sig := &oqs.Signature{}

	err := sig.Init(signatureAlg, m.PQPrivateKey)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// PQKeyBundle holds both a legacy and post-quantum key
type PQKeyBundle struct {
	LegacyPrivateKey *ecdsa.PrivateKey
	PQPrivateKey     []byte
}

// LegacyKeyPEM returns the legacy key, encoded in PEM format
func (p *PQKeyBundle) LegacyKeyPEM() ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(p.LegacyPrivateKey)
	if err != nil {
		return nil, err
	}

	pemBytes := &bytes.Buffer{}
	err = pem.Encode(pemBytes, &pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})
	if err != nil {
		return nil, err
	}

	return pemBytes.Bytes(), nil
}
