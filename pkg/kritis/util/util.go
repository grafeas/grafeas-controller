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

package util

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/attestation"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/grafeas"
	pkg "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/package"
	"google.golang.org/genproto/googleapis/devtools/containeranalysis/v1beta1/vulnerability"
)

// GetVulnerabilityFromOccurrence returns a metadata.Vulnerability from a grafeas Occurrence.
func GetVulnerabilityFromOccurrence(occ *grafeas.Occurrence) *metadata.Vulnerability {
	vulnDetails := occ.GetVulnerability()
	if vulnDetails == nil {
		return nil
	}
	hasFixAvailable := IsFixAvailable(vulnDetails.GetPackageIssue())
	vulnerability := metadata.Vulnerability{
		Severity:        vulnerability.Severity_name[int32(vulnDetails.Severity)],
		HasFixAvailable: hasFixAvailable,
		CVE:             occ.GetNoteName(),
	}
	return &vulnerability
}

// IsFixAvailable returns whether or not a vulnerability has a fix available.
func IsFixAvailable(pis []*vulnerability.PackageIssue) bool {
	for _, pi := range pis {
		if pi.GetFixedLocation().GetVersion().Kind == pkg.Version_MAXIMUM {
			// If FixedLocation.Version.Kind = MAXIMUM then no fix is available. Return false
			return false
		}
	}
	return true
}

// GetResourceURL returns the URL to a container image.
func GetResourceURL(containerImage string) string {
	return fmt.Sprintf("%s%s", constants.ResourceURLPrefix, containerImage)
}

// GetResource returns a grafeas Resource for a container image.
func GetResource(image string) *grafeas.Resource {
	return &grafeas.Resource{Uri: GetResourceURL(image)}
}

// GetPGPAttestationFromOccurrence returns a metadata.PgpAttestation from a grafeas Occurrence.
func GetPGPAttestationFromOccurrence(occ *grafeas.Occurrence) metadata.PGPAttestation {
	pgp := occ.GetAttestation().GetAttestation().GetPgpSignedAttestation()
	return metadata.PGPAttestation{
		Signature: pgp.GetSignature(),
		KeyID:     pgp.GetPgpKeyId(),
		OccID:     occ.GetName(),
	}
}

// CreateAttestationSignature returns an attestation signature for an image.
func CreateAttestationSignature(image string, pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	hostSig, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		return "", err
	}
	hostStr, err := hostSig.JSON()
	if err != nil {
		return "", err
	}
	return attestation.CreateMessageAttestation(pgpSigningKey.PublicKey, pgpSigningKey.PrivateKey, hostStr)
}

// GetAttestationKeyFingerprint returns a PGP fingerprint for the attestation signing key.
func GetAttestationKeyFingerprint(pgpSigningKey *secrets.PGPSigningSecret) (string, error) {
	return attestation.GetKeyFingerprint(pgpSigningKey.PublicKey)
}

// GetOrCreateAttestationNote returns a note if exists and creates one if it does not exist.
func GetOrCreateAttestationNote(c metadata.Fetcher, a *v1beta1.AttestationAuthority) (*grafeas.Note, error) {
	n, err := c.AttestationNote(a)
	if err == nil {
		return n, nil
	}
	return c.CreateAttestationNote(a)
}
