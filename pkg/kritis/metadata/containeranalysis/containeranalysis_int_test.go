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

package containeranalysis

import (
	"fmt"
	"testing"

	kritisv1beta1 "github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	IntTestNoteName = "test-aa-note"
	IntAPI          = "testv1"
	IntProject      = "kritis-int-test"
)

func TestGetVulnerabilities(t *testing.T) {
	d, err := NewContainerAnalysisClient()
	if err != nil {
		t.Fatalf("Could not initialize the client %s", err)
	}
	vuln, err := d.GetVulnerabilities("gcr.io/gcp-runtimes/go1-builder@sha256:81540dfae4d3675c06113edf90c6658a1f290c2c8ebccd19902ddab3f959aa71")
	if err != nil {
		t.Fatalf("Found err %s", err)
	}
	if vuln == nil {
		t.Fatalf("Expected some vulnerabilities. Nil found")
	}
}

func TestCreateAttestationNoteAndOccurrence(t *testing.T) {
	d, err := NewContainerAnalysisClient()
	aa := &kritisv1beta1.AttestationAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name: IntTestNoteName,
		},
		Spec: kritisv1beta1.AttestationAuthoritySpec{
			NoteReference: fmt.Sprintf("%s/projects/%s", IntAPI, IntProject),
		},
	}
	if err != nil {
		t.Fatalf("Could not initialize the client %s", err)
	}
	_, err = d.CreateAttestationNote(aa)
	if err != nil {
		t.Fatalf("Unexpected error while creating Note %v", err)
	}
	defer d.DeleteAttestationNote(aa)
	note, err := d.GetAttestationNote(aa)
	expectedNoteName := fmt.Sprintf("projects/%s/notes/%s", IntProject, IntTestNoteName)
	if note.Name != expectedNoteName {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, note.Name)
	}
	actualHint := note.GetAttestationAuthority().Hint.GetHumanReadableName()
	if actualHint != IntTestNoteName {
		t.Fatalf("Expected %s.\n Got %s", expectedNoteName, actualHint)
	}
	// Test Create Attestation Occurence
	pub, priv := testutil.CreateKeyPair(t, "test")
	secret := &secrets.PGPSigningSecret{
		PrivateKey: priv,
		PublicKey:  pub,
		SecretName: "test",
	}

	occ, err := d.CreateAttestationOccurence(note, testutil.IntTestImage, secret)
	if err != nil {
		t.Fatalf("Unexpected error while creating Occurence %v", err)
	}
	defer d.DeleteOccurrence(occ.GetName())
	occurrences, err := d.GetAttestations(testutil.IntTestImage)
	if err != nil {
		t.Fatalf("Unexpected error while listing Occ %v", err)
	}
	if occurrences == nil {
		t.Fatal("Shd have created atleast 1 occurrence")
	}

	occurrences, err = d.GetAttestations("gcr.io/kritis-int-test/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8")
	fmt.Println("occ", occurrences)
	for _, occ := range occurrences {
		fmt.Println(d.DeleteOccurrence(occ.OccName))
	}
	occurrences, err = d.GetAttestations("gcr.io/tejaldesai-personal/java-with-vuln@sha256:b3f3eccfd27c9864312af3796067e7db28007a1566e1e042c5862eed3ff1b2c8")
	fmt.Println(occurrences)
}
