/*
Copyright 2018 Google LLC

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

package attestation

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// PgpKey struct converts the base64 encoded PEM keys into openpgp private and
// public keys. Kubernetes Secrets are stored as base64 encoded PEM keys.
type PgpKey struct {
	privateKey *packet.PrivateKey
	publicKey  *packet.PublicKey
}

func NewPgpKey(privateKeyEnc string, publicKeyEnc string) (*PgpKey, error) {
	var publicKey *packet.PublicKey = nil
	var privateKey *packet.PrivateKey = nil

	if privateKeyEnc != "" {
		pemPrivateKey, err := base64.StdEncoding.DecodeString(privateKeyEnc)
		if err != nil {
			return nil, err
		}
		privateKey, err = parsePrivateKey(string(pemPrivateKey))
		if err != nil {
			return nil, err
		}
	}
	if publicKeyEnc != "" {
		pemPublicKey, err := base64.StdEncoding.DecodeString(publicKeyEnc)
		if err != nil {
			return nil, err
		}
		publicKey, err = parsePublicKey(string(pemPublicKey))
		if err != nil {
			return nil, err
		}
	}
	return &PgpKey{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (key *PgpKey) PublicKey() *packet.PublicKey {
	return key.publicKey
}

func (key *PgpKey) PrivateKey() *packet.PrivateKey {
	return key.privateKey
}

func parsePublicKey(publicKey string) (*packet.PublicKey, error) {
	pkt, err := parseKey(publicKey, openpgp.PublicKeyType)
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Not a public key")
	}
	return key, nil
}

func parsePrivateKey(privateKey string) (*packet.PrivateKey, error) {
	pkt, err := parseKey(privateKey, openpgp.PrivateKeyType)
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Not a private Key")
	}
	return key, nil
}

func parseKey(key string, keytype string) (packet.Packet, error) {
	r := strings.NewReader(key)
	block, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}
	if block.Type != keytype {
		return nil, err
	}
	reader := packet.NewReader(block.Body)
	return reader.Next()
}
