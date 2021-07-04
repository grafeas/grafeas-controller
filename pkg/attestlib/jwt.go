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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

func getAlgName(alg SignatureAlgorithm) string {
	switch alg {
	case RsaPss2048Sha256, RsaPss3072Sha256, RsaPss4096Sha256:
		return "PS256"
	case RsaPss4096Sha512:
		return "PS512"
	case RsaSignPkcs12048Sha256, RsaSignPkcs13072Sha256, RsaSignPkcs14096Sha256:
		return "RS256"
	case RsaSignPkcs14096Sha512:
		return "RS512"
	case EcdsaP256Sha256:
		return "ES256"
	case EcdsaP384Sha384:
		return "ES384"
	case EcdsaP521Sha512:
		return "ES512"
	default:
		return "Algorithm Not Supported"

	}
}

type jwtSigner struct {
	privateKey         interface{}
	publicKeyID        string
	signatureAlgorithm SignatureAlgorithm
}

// NewJwtSigner creates a Signer interface for JWT Attestations. `privateKey`
// contains the PEM-encoded private key. `publicKeyID` is the ID of the public
// key that can verify the Attestation signature. In most cases, publicKeyID should be left empty and will be generated automatically.
func NewJwtSigner(privateKey []byte, alg SignatureAlgorithm, publicKeyID string) (Signer, error) {
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
	return &jwtSigner{
		privateKey:         key,
		publicKeyID:        publicKeyID,
		signatureAlgorithm: alg,
	}, nil
}

// CreateAttestation creates a signed JWT Attestation. See Signer for more details.
// jsonJwtBody is the second section in the JWT. This should contain the following claims:
// "sub" = container:digest:sha256:<my-image-digest>,  "aud" : "//binaryauthorization.googleapis.com", "attestationType" : "claimless"
func (s *jwtSigner) CreateAttestation(jsonJwtBody []byte) (*Attestation, error) {
	type headerTemplate struct {
		typ, alg, kid string
	}
	header := headerTemplate{
		typ: "JWT",
		alg: getAlgName(s.signatureAlgorithm),
		kid: s.publicKeyID,
	}

	headerJson, err := json.Marshal(header)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling header")
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJson)
	jsonJwtBodyBase64 := base64.RawURLEncoding.EncodeToString(jsonJwtBody)
	signature, err := createDetachedSignature(s.privateKey, []byte(headerBase64+"."+jsonJwtBodyBase64), s.signatureAlgorithm)
	if err != nil {
		return nil, errors.Wrap(err, "error creating signature")
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)
	jwt := headerBase64 + "." + jsonJwtBodyBase64 + "." + signatureBase64
	return &Attestation{
		PublicKeyID: s.publicKeyID,
		Signature:   []byte(jwt),
	}, nil
}

func checkHeader(headerIn []byte, publicKey PublicKey) error {
	type headerTemplate struct {
		Typ, Alg, Kid, Crit string
	}
	var jsonHeader headerTemplate
	err := json.Unmarshal(headerIn, &jsonHeader)
	if err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	if jsonHeader.Crit != "" {
		return errors.New("crit field not supported")
	}
	if jsonHeader.Typ != "JWT" {
		return errors.New("typ field invalid")
	}
	if jsonHeader.Alg != getAlgName(publicKey.SignatureAlgorithm) {
		return errors.New("alg field does not match the algorithm of the public key")
	}
	if jsonHeader.Kid != publicKey.ID {
		return errors.New("kid field does not match the public key ID")
	}

	return nil

}

type jwtVerifierImpl struct{}

func (v jwtVerifierImpl) verifyJwt(signature []byte, publicKey PublicKey) ([]byte, error) {
	parts := bytes.Split(signature, []byte("."))
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT")
	}
	header, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode header")
	}
	err = checkHeader(header, publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid header")
	}
	// Decode and return payload once verifyDetached is implimented.
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode payload")
	}
	verifyDetached(parts[2], publicKey.KeyData, publicKey.SignatureAlgorithm, append(parts[0], parts[1]...))
	return nil, errors.New("unimplemented")
}
