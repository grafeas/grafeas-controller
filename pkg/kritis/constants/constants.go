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

package constants

const (
	// Vulnerability level AllowAll is the value used to allow all images with CVEs
	AllowAll = "ALLOW_ALL"
	// Vulnerability level BlockAll is the value used to block all images with CVEs,
	// except for allowlisted CVEs
	BlockAll = "BLOCK_ALL"
	// Vulnerability level Critical
	Critical = "CRITICAL"
	// Vulnerability level High
	High = "HIGH"
	// Vulnerability level Medium
	Medium = "MEDIUM"
	// Vulnerability level Low
	Low = "LOW"

	// InvalidImageSecPolicy is the key for labels and annotations
	InvalidImageSecPolicy           = "kritis.grafeas.io/invalidImageSecPolicy"
	InvalidImageSecPolicyLabelValue = "invalidImageSecPolicy"

	// ImageAttestation is the key for labels for indication attestaions.
	ImageAttestation             = "kritis.grafeas.io/attestation"
	NoAttestationsLabelValue     = "notAttested"
	PreviouslyAttestedLabelValue = "attested"

	// Breakglass is the key for the breakglass annotation
	Breakglass = "kritis.grafeas.io/breakglass"

	// A list of label values
	PreviouslyAttestedAnnotation = "Previously attested."
	NoAttestationsAnnotation     = "No valid attestations present. This pod will not be able to restart in future"

	// Atomic Container Signature type
	AtomicContainerSigType = "atomic container signature"

	// Constants for Metadata Library
	PageSize          = int32(100)
	ResourceURLPrefix = "https://"

	// Constants relevant for the GCB event parser
	CloudSourceRepoPattern = "https://source.developers.google.com/p/%s/r/%s%s"

	// Constants for the configuration of which metadata backend
	ContainerAnalysisMetadata = "containerAnalysis"
	GrafeasMetadata           = "grafeas"
)

var (
	// GlobalImageAllowlist is a list of images that are globally allowed
	// They should always pass the webhook check
	GlobalImageAllowlist = []string{"gcr.io/kritis-project/kritis-server",
		"gcr.io/kritis-project/preinstall",
		"gcr.io/kritis-project/postinstall",
		"gcr.io/kritis-project/predelete",
		"us.gcr.io/grafeas/grafeas-server",
	}
)
