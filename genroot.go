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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// GenerateMultiKeyRootCert creates a new root certificate with a Ed25519 legacy signature
// and a falcon-1024 post-quantum signature
func GenerateMultiKeyRootCert() (*MultiKeyCertBundle, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	legacyPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	legacyPublicKey := legacyPrivateKey.Public()

	derPublicKey, err := x509.MarshalPKIXPublicKey(legacyPublicKey)
	if err != nil {
		return nil, err
	}

	sig := &oqs.Signature{}

	err = sig.Init(signatureAlg, nil)
	if err != nil {
		return nil, err
	}

	pqPublicKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	pqPrivateKey := sig.ExportSecretKey()

	pqSignature, err := sig.Sign(derPublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	tmpl := &x509.Certificate{
		Version: 2,

		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName: "multi-key-root",
		},

		IsCA:                  true,
		MaxPathLen:            3,
		BasicConstraintsValid: true,

		KeyUsage: x509.KeyUsageCertSign,

		NotBefore: now,
		NotAfter:  now.Add(time.Hour * 24 * 365 * 25), // 25 years

		PublicKeyAlgorithm: x509.Ed25519,

		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidPQPublicKey,
				Value: pqPublicKey,
			},
			{
				Id:    oidPQSignature,
				Value: pqSignature,
			},
		},
	}

	rawIssuedCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, legacyPublicKey, legacyPrivateKey)
	if err != nil {
		return nil, err
	}

	parsedIssuedCert, err := x509.ParseCertificate(rawIssuedCert)
	if err != nil {
		return nil, err
	}

	pemBytes := &bytes.Buffer{}
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: rawIssuedCert})
	return &MultiKeyCertBundle{
		ParsedCert: parsedIssuedCert,

		CertPEM: pemBytes.String(),
		CertDER: rawIssuedCert,

		LegacyPublicKey: legacyPublicKey,
		PQPublicKey:     pqPublicKey,

		PQKeyBundle: PQKeyBundle{
			LegacyPrivateKey: legacyPrivateKey,
			PQPrivateKey:     pqPrivateKey,
		},
	}, nil
}
