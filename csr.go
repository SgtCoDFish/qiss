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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// GenerateMultiKeyCSR creates an ecdsa/pq multi-key CSR, returning the DER-encoded
// CSR and the generated keys
func GenerateMultiKeyCSR(commonName string, dnsNames []string) ([]byte, PQKeyBundle, error) {
	legacyPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	legacyPublicKey := legacyPrivateKey.Public()

	derPublicKey, err := x509.MarshalPKIXPublicKey(legacyPublicKey)
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	sig := &oqs.Signature{}

	err = sig.Init(signatureAlg, nil)
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	pqPublicKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	pqSignature, err := sig.Sign(derPublicKey)
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		PublicKey: legacyPublicKey,
		DNSNames:  dnsNames,
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

	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, legacyPrivateKey)
	if err != nil {
		return nil, PQKeyBundle{}, err
	}

	return csr, PQKeyBundle{
		LegacyPrivateKey: legacyPrivateKey,
		PQPrivateKey:     sig.ExportSecretKey(),
	}, nil
}

// ValidateMultiKeyCSR parses the given DER encoded CSR, and then validates that the
// pq key and signature extensions are present and valid. Returns the parsed csr on success.
func ValidateMultiKeyDERCSR(derCSR []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return nil, err
	}

	return ValidateMultiKeyCSR(csr)
}

func extractPQExtensionsFromCSR(csr *x509.CertificateRequest) ([]byte, []byte, error) {
	var pqPublicKey []byte
	var pqSignature []byte

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidPQPublicKey) {
			pqPublicKey = ext.Value
		} else if ext.Id.Equal(oidPQSignature) {
			pqSignature = ext.Value
		}
	}

	if len(pqPublicKey) == 0 {
		return nil, nil, fmt.Errorf("missing required multikey extension: oidPQPublicKey")
	}

	if len(pqSignature) == 0 {
		return nil, nil, fmt.Errorf("missing required multikey extension: oidPQSignature")
	}

	return pqPublicKey, pqSignature, nil
}

// ValidateMultiKeyCSR validates that the pq key and signature extensions are present
// and valid in the given CSR. Returns the same CSR on success.
func ValidateMultiKeyCSR(csr *x509.CertificateRequest) (*x509.CertificateRequest, error) {
	pqPublicKey, pqSignature, err := extractPQExtensionsFromCSR(csr)
	if err != nil {
		return nil, err
	}

	// at this point pqSignature IS NOT TRUSTED and cannot be safely used until checked
	sig := &oqs.Signature{}

	err = sig.Init(signatureAlg, nil)
	if err != nil {
		return nil, err
	}

	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("unsupported legacy public key type")
	}

	legacyPublicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid legacy public key")
	}

	derPublicKey, err := x509.MarshalPKIXPublicKey(legacyPublicKey)
	if err != nil {
		return nil, err
	}

	// check that the pq signature is of the legacy public key
	ok, err = sig.Verify(derPublicKey, pqSignature, pqPublicKey)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("invalid post-quantum signature")
	}

	return csr, nil
}

// SignCSR takes a parsed certificate request, validates it and signs it using both legacy
// and post-quantum signatures
func SignCSR(csr *x509.CertificateRequest, signingBundle *MultiKeyCertBundle) ([]byte, error) {
	// must first validate the pq extensions in the CSR to verify that the signer
	// had access to the PQ private key when they created the CSR
	if _, err := ValidateMultiKeyCSR(csr); err != nil {
		return nil, err
	}

	sig, err := signingBundle.OQSSignature()
	if err != nil {
		return nil, err
	}

	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("unsupported legacy public key type")
	}

	legacyPublicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid legacy public key")
	}

	derPublicKey, err := x509.MarshalPKIXPublicKey(legacyPublicKey)
	if err != nil {
		return nil, err
	}

	pqPublicKey, _, err := extractPQExtensionsFromCSR(csr)
	if err != nil {
		return nil, err
	}

	pqSignature, err := sig.Sign(derPublicKey)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)

	tmpl := &x509.Certificate{
		Version: 2,

		SerialNumber: serialNumber,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		Subject: csr.Subject,

		IsCA:                  false,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		DNSNames: csr.DNSNames,

		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidPQPublicKey,
				Value: pqPublicKey,
			},
			{
				Id: oidPQSignature,
				// subtle: this is the signature created by the private key of the issuer,
				// not the proof signature present in the CSR (which is discarded)
				Value: pqSignature,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, signingBundle.ParsedCert, csr.PublicKey, signingBundle.LegacyPrivateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}
