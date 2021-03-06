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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
)

const rsaPkcs1Key = "RSA PRIVATE KEY"
const ecPkcs1Key = "EC PRIVATE KEY"
const pkcs8Key = "PRIVATE KEY"

func parsePkixPrivateKeyPem(privateKey []byte) (interface{}, error) {
	der, rest := pem.Decode(privateKey)

	if len(rest) != 0 {
		return nil, errors.New("expected one public key")
	}
	switch der.Type {
	case rsaPkcs1Key:
		key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse rsa pkcs1 private key")
		}
		return key, nil
	case ecPkcs1Key:
		key, err := x509.ParseECPrivateKey(der.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse ecdsa pkcs1 private key")
		}
		return key, nil
	case pkcs8Key:
		key, err := x509.ParsePKCS8PrivateKey(der.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse pkcs8 private key")
		}
		return key, nil
	default:
		return nil, errors.New("unexpected key type")
	}
}

// key should be of type *rsa.PrivateKey, *ecdsa.PrivateKey or []byte. If []byte the key should be a public key.
func generatePkixPublicKeyId(key interface{}) (string, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		rsaKey := key.(*rsa.PrivateKey)
		publicKeyMaterial, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "marshal rsa public key error")
		}
		dgst := sha256.Sum256(publicKeyMaterial)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		return fmt.Sprintf("ni:///sha-256;%s", base64Dgst), nil
	case *ecdsa.PrivateKey:
		ecKey := key.(*ecdsa.PrivateKey)
		publicKeyMaterial, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "marshal ecdsa public key error")
		}
		dgst := sha256.Sum256(publicKeyMaterial)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		return fmt.Sprintf("ni:///sha-256;%s", base64Dgst), nil
	case []byte:
		der, rest := pem.Decode(key.([]byte))
		if len(rest) != 0 {
			return "", errors.New("expected one public key")
		}
		dgst := sha256.Sum256(der.Bytes)
		base64Dgst := base64.RawURLEncoding.EncodeToString(dgst[:])
		return fmt.Sprintf("ni:///sha-256;%s", base64Dgst), nil
	default:
		return "", errors.New("unexpected key type")
	}
}
