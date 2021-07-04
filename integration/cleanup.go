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
	"fmt"
	"os/exec"

	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	v1 "k8s.io/api/core/v1"
)

func cleanupInstall(ns *v1.Namespace) error {
	var resources = []struct {
		Type      string
		Name      string
		Namespace *v1.Namespace
	}{
		{"validatingwebhookconfiguration", fmt.Sprintf("kritis-validation-hook-%s", ns.Name), nil},
		{"validatingwebhookconfiguration", fmt.Sprintf("kritis-validation-hook-deployments-%s", ns.Name), nil},
		{"csr", fmt.Sprintf("tls-webhook-secret-cert-%s", ns.Name), nil},
		{"secret", aaSecret, ns},
	}
	for _, r := range resources {
		if err := deleteObject(r.Type, r.Name, r.Namespace); err != nil {
			return err
		}
	}
	return nil
}

func deleteObject(object, name string, ns *v1.Namespace) error {
	deleteCmd := exec.Command("kubectl", "delete", object, name)
	if ns != nil {
		deleteCmd.Args = append(deleteCmd.Args, []string{"-n", ns.Name}...)

		_, err := integration_util.RunCmdOut(deleteCmd)
		if err != nil {
			return fmt.Errorf("error deleting %s %s in namespace %s: %v", object, name, ns.Name, err)
		}
	} else {
		_, err := integration_util.RunCmdOut(deleteCmd)
		if err != nil {
			return fmt.Errorf("error deleting %s %s: %v", object, name, err)
		}
	}
	return nil
}
