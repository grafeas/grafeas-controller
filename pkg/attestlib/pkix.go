/*
Copyright 2020 Google LLC

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

package attestlib

import (
	"github.com/pkg/errors"
)

type pkixSigner struct {
	privateKey         interface{}
	publicKeyID        string
	signatureAlgorithm SignatureAlgorithm
}

// NewPkixSigner creates a Signer interface for PKIX Attestations. `privateKey`
// contains the PEM-encoded private key. `publicKeyID` is the ID of the public
// key that can verify the Attestation signature. In most cases, publicKeyID should be left empty and will be generated automatically.
func NewPkixSigner(privateKey []byte, alg SignatureAlgorithm, publicKeyID string) (Signer, error) {
	key, err := parsePkixPrivateKeyPem(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	// If no ID is provided one is computed based on the default digest-based URI extracted from the public key material
	if len(publicKeyID) == 0 {
		publicKeyID, err = generatePkixPublicKeyId(key)
		if err != nil {
			return nil, errors.Wrap(err, "error generating public key id")
		}
	}
	return &pkixSigner{
		privateKey:         key,
		publicKeyID:        publicKeyID,
		signatureAlgorithm: alg,
	}, nil
}

// CreateAttestation creates a signed PKIX Attestation. See Signer for more details.
func (s *pkixSigner) CreateAttestation(payload []byte) (*Attestation, error) {
	signature, err := createDetachedSignature(s.privateKey, payload, s.signatureAlgorithm)
	if err != nil {
		return nil, errors.Wrap(err, "error creating signature")
	}
	return &Attestation{
		PublicKeyID:       s.publicKeyID,
		Signature:         signature,
		SerializedPayload: payload,
	}, nil
}

type pkixVerifierImpl struct{}

func (v pkixVerifierImpl) verifyPkix(signature []byte, payload []byte, publicKey PublicKey) error {
	err := verifyDetached(signature, publicKey.KeyData, publicKey.SignatureAlgorithm, payload)
	if err != nil {
		return errors.Wrap(err, "error verifying signature")
	}
	return nil
}
