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
package integration

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/metadata/containeranalysis"
)

func checkAndDeleteAttestations(t *testing.T, images []string) {
	if len(images) == 0 {
		return
	}
	client, err := containeranalysis.NewContainerAnalysisClient()
	if err != nil {
		t.Fatalf("Unexpected error while fetching client %v", err)
	}
	for _, i := range images {
		occs, err := client.GetAttestations(i)
		if err != nil {
			t.Fatalf("Unexpected error while listing attestations for image %s, %v", i, err)
		}
		if occs != nil {
			t.Errorf("expected image %s to be attested. No attestations found.", i)
		}
		for _, o := range occs {
			client.DeleteOccurrence(o.OccName)
		}
	}
}
