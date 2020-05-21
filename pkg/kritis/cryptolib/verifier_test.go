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

package cryptolib

import (
	"testing"

	"github.com/pkg/errors"
)

const qualifiedImage = "gcr.io/image/digest@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func TestVerifyAttestation(t *testing.T) {
	att := &Attestation{
		PublicKeyID:       "key-id",
		Signature:         []byte("signature"),
		SerializedPayload: []byte("payload"),
	}
	matchingKey := NewPublicKey(Pkix, []byte("key-data"), "key-id")
	otherMatchingKey := NewPublicKey(Pkix, []byte("key-data-other"), "key-id")
	nonmatchingKey := NewPublicKey(Pkix, []byte("key-data-other"), "key-id-other")

	tcs := []struct {
		name        string
		att         *Attestation
		publicKeys  []PublicKey
		verifyErr   bool
		expectedErr bool
	}{
		{
			name:        "single key match",
			att:         att,
			publicKeys:  []PublicKey{matchingKey},
			verifyErr:   false,
			expectedErr: false,
		},
		{
			name:        "matching and nonmatching keys",
			att:         att,
			publicKeys:  []PublicKey{nonmatchingKey, matchingKey},
			verifyErr:   false,
			expectedErr: false,
		},
		{
			// This is a possibility with user-provided IDs
			name:        "different keys with same ID",
			att:         att,
			publicKeys:  []PublicKey{matchingKey, otherMatchingKey},
			verifyErr:   false,
			expectedErr: false,
		},
		{
			name:        "key not found",
			att:         att,
			publicKeys:  []PublicKey{nonmatchingKey},
			verifyErr:   false,
			expectedErr: true,
		},
		{
			name:        "error in verification",
			att:         att,
			publicKeys:  []PublicKey{matchingKey},
			verifyErr:   true,
			expectedErr: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v := verifier{ImageDigest: qualifiedImage, PublicKeys: indexPublicKeysByID(tc.publicKeys)}
			v.pkixVerifier = mockPkixVerifier{shouldErr: tc.verifyErr}
			v.authenticatedAttChecker = mockAuthAttChecker{}

			err := v.VerifyAttestation(tc.att)
			if tc.expectedErr != (err != nil) {
				t.Errorf("VerifyAttestation(_) got %v, wanted error? = %v", err, tc.expectedErr)
			}
		})
	}
}

type mockPkixVerifier struct {
	shouldErr bool
}

func (v mockPkixVerifier) verifyPkix([]byte, []byte, []byte) error {
	if v.shouldErr {
		return errors.New("error verifying PKIX")
	}
	return nil
}

type mockAuthAttChecker struct{}

func (c mockAuthAttChecker) checkAuthenticatedAttestation(payload []byte, imageName string, imageDigest string, convert convertFunc) error {
	return nil
}
