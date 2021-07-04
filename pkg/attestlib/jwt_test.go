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
	"testing"
)

const goodJwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAibXktc2lnbmluZy1rZXkiIH0K.eyAic3ViIjogImNvbnRhaW5lcjpkaWdlc3Q6c2hhMjU2OmZha2UtZGlnZXN0IiwgImF1ZCI6ICIvL2JpbmFyeWF1dGhvcml6YXRpb24uZ29vZ2xlYXBpcy5jb20iLCAiYXR0ZXN0YXRpb25UeXBlIjogIlRCRCIsICJhdHRlc3RhdGlvbiI6ICIiIH0K.somesignature"
const jwtWithInvalidHeaderTYP = "eyAgImFsZyI6ICJFUzI1NiIsICJ0eXAiOiAiQkFEVFlQRSIsICJraWQiOiAibXktc2lnbmluZy1rZXkiIH0K.eyAic3ViIjogImNvbnRhaW5lcjpkaWdlc3Q6c2hhMjU2OmZha2UtZGlnZXN0IiwgImF1ZCI6ICIvL2JpbmFyeWF1dGhvcml6YXRpb24uZ29vZ2xlYXBpcy5jb20iLCAiYXR0ZXN0YXRpb25UeXBlIjogIlRCRCIsICJhdHRlc3RhdGlvbiI6ICIiIH0K.somesignature"
const jwtWithCrit = "eyJhbGciOiJFUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoibXktc2lnbmluZy1rZXkiLCAiY3JpdCI6ICJsaXN0LW9mLWZpZWxkcyJ9Cg.eyAic3ViIjogImNvbnRhaW5lcjpkaWdlc3Q6c2hhMjU2OmZha2UtZGlnZXN0IiwgImF1ZCI6ICIvL2JpbmFyeWF1dGhvcml6YXRpb24uZ29vZ2xlYXBpcy5jb20iLCAiYXR0ZXN0YXRpb25UeXBlIjogIlRCRCIsICJhdHRlc3RhdGlvbiI6ICIiIH0K.someisgnature"

var goodPubKey = PublicKey{
	AuthenticatorType:  Jwt,
	SignatureAlgorithm: EcdsaP256Sha256,
	ID:                 "my-signing-key",
	KeyData:            []byte("some-key"),
}

func TestVerifyJWT(t *testing.T) {
	tcs := []struct {
		name          string
		jwt           []byte
		pubkey        PublicKey
		expectedError bool
	}{
		{
			name:          "valid JWT and Public Key",
			jwt:           []byte(goodJwt),
			pubkey:        goodPubKey,
			expectedError: true, // change once verifyDetached is implimented.
		}, {
			name:          "invalid JWT length",
			jwt:           []byte("too.many.parts.here"),
			pubkey:        goodPubKey,
			expectedError: true,
		}, {
			name: "PublicKey AuthenticatorType does not match ALG in JWT header",
			jwt:  []byte(goodJwt),
			pubkey: PublicKey{
				AuthenticatorType:  Jwt,
				SignatureAlgorithm: RsaSignPkcs14096Sha256,
				ID:                 "my-signing-key",
				KeyData:            []byte("some-key"),
			},
			expectedError: true,
		}, {
			name: "PublicKey ID does not match KID in JWT header",
			jwt:  []byte(goodJwt),
			pubkey: PublicKey{
				AuthenticatorType:  Jwt,
				SignatureAlgorithm: EcdsaP256Sha256,
				ID:                 "some-key-id",
				KeyData:            []byte("some-key"),
			},
			expectedError: true,
		}, {
			name:          "Invalid TYP field",
			jwt:           []byte(jwtWithInvalidHeaderTYP),
			pubkey:        goodPubKey,
			expectedError: true,
		}, {
			name:          "Invalid Base64Encoding",
			jwt:           []byte("aaaaa.aaaa.aaaa"), // header has 5 a's which should return error from DecodeBase64
			pubkey:        goodPubKey,
			expectedError: true,
		}, {
			name:          "Fails with crit field present",
			jwt:           []byte(jwtWithCrit),
			pubkey:        goodPubKey,
			expectedError: true,
		},
	}

	v := jwtVerifierImpl{}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.verifyJwt(tc.jwt, tc.pubkey)
			if tc.expectedError {
				if err == nil {
					t.Errorf("Passed when failure expected")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

			}
		})
	}
}

func TestNewJwtSigner(t *testing.T) {
	tcs := []struct {
		name          string
		key           []byte
		publicKeyId   string
		alg           SignatureAlgorithm
		expectedError bool
	}{
		{
			name:          "new jwt signer success",
			key:           []byte(rsa2048PrivateKey),
			publicKeyId:   "kid",
			alg:           RsaSignPkcs12048Sha256,
			expectedError: false,
		},
		{
			name:          "new jwt signer with no key id success",
			key:           []byte(rsa2048PrivateKey),
			publicKeyId:   "",
			alg:           RsaSignPkcs12048Sha256,
			expectedError: false,
		},
		{
			name:          "new jwt signer with bad key fails",
			key:           []byte("some-key"),
			publicKeyId:   "",
			alg:           RsaSignPkcs12048Sha256,
			expectedError: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJwtSigner(tc.key, tc.alg, tc.publicKeyId)
			if tc.expectedError {
				if err == nil {
					t.Errorf("NewJwtSigner(...)=nil, expected non nil")
				}
			} else {
				if err != nil {
					t.Errorf("NewJwtSigner(...)=%v, expected nil", err)
				}
			}
		})
	}
}

func TestCreateJwtAttestation(t *testing.T) {
	signer, err := NewJwtSigner([]byte(rsa2048PrivateKey), RsaSignPkcs12048Sha256, "kid")
	if err != nil {
		t.Fatalf("failed to create signer")
	}
	attestation, err := signer.CreateAttestation([]byte(payload))
	if err != nil {
		t.Errorf("CreateAttestation(..)=%v, expected nil", err)
	} else if attestation.PublicKeyID != "kid" {
		t.Errorf("attestation.PublicKeyID=%v, expected kid", attestation.PublicKeyID)
	}
}
