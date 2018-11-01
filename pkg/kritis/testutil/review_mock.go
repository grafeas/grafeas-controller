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

package testutil

import (
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"k8s.io/api/core/v1"
)

// ReviewerMock is mock reviewer.Reviewer client.
type ReviewerMock struct {
	hasErr  bool
	message string
}

// NewReviewer returns a mock reviewer.Reviewer client.
func NewReviewer(r bool, s string) *ReviewerMock {
	return &ReviewerMock{
		hasErr:  r,
		message: s,
	}
}

// Review reviews a set of images against a set of policies
func (r *ReviewerMock) Review(images []string, isps []v1beta1.ImageSecurityPolicy, pod *v1.Pod) error {
	if !r.hasErr {
		return nil
	}
	return fmt.Errorf(r.message)
}
