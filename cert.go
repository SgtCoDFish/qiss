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
	"crypto/x509"
	"fmt"
)

func extractPQExtensionsFromCertificate(cert *x509.Certificate) ([]byte, []byte, error) {
	var pqPublicKey []byte
	var pqSignature []byte

	for _, ext := range cert.Extensions {
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
