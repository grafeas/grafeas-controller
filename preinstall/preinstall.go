package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

func deleteExistingObjects() {
	csrCmd := exec.Command("kubectl", "get", "csr", csrName)
	csrCmd.Stderr = os.Stderr
	_, err := csrCmd.Output()
	fmt.Println(err)
	if err == nil {
		deleteCSRCmd := exec.Command("kubectl", "delete", "csr", csrName)
		RunCommand(deleteCSRCmd)
	}
	secretCmd := exec.Command("kubectl", "get", "secret", tlsSecretName)
	secretCmd.Stderr = os.Stderr
	_, err = secretCmd.Output()
	fmt.Println(err)
	if err == nil {
		deleteSecretCmd := exec.Command("kubectl", "delete", "secret", tlsSecretName)
		RunCommand(deleteSecretCmd)
	}
}

func createCertificates() {
	cert := `{
"hosts": [
    "kritis-validation-hook",
    "kritis-validation-hook.kube-system",
    "kritis-validation-hook.%s",
    "kritis-validation-hook.%s.svc"
],
"key": {
	"algo": "ecdsa",
	"size": 256
}
}`
	cert = fmt.Sprintf(cert, namespace, namespace)
	certCmd := exec.Command("cfssl", "genkey", "-")
	certCmd.Stdin = bytes.NewReader([]byte(cert))
	output := RunCommand(certCmd)

	serverCmd := exec.Command("cfssljson", "-bare", "server")
	serverCmd.Stdin = bytes.NewReader(output)
	RunCommand(serverCmd)
}

func createCertificateSigningRequest() {
	certificate := retrieveRequestCertificate()
	csr := `apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
    name: %s
spec:
    groups:
    - system:authenticated
    request: %s
    usages:
    - digital signature
    - key encipherment
    - server auth`
	csr = fmt.Sprintf(csr, csrName, certificate)

	kubectlCmd := exec.Command("kubectl", "apply", "-f", "-")
	kubectlCmd.Stdin = bytes.NewReader([]byte(csr))
	fmt.Println(csr)
	RunCommand(kubectlCmd)
}

func approveCertificateSigningRequest() {
	approvalCmd := exec.Command("kubectl", "certificate", "approve", csrName)
	RunCommand(approvalCmd)
}

func retrieveRequestCertificate() string {
	contents, err := ioutil.ReadFile("server.csr")
	if err != nil {
		logrus.Fatalf("error trying to read contents of server.csr: %v", err)
	}
	// base64 encode the contents
	encodedLen := base64.StdEncoding.EncodedLen(len(contents))
	encoded := make([]byte, encodedLen)
	base64.StdEncoding.Encode(encoded, contents)
	// trim any new lines off the end
	return string(encoded)
}

func createTLSSecret() {
	retrieveCertCmd := exec.Command("kubectl", "get", "csr", csrName, "-o", "jsonpath='{.status.certificate}'")
	cert := RunCommand(retrieveCertCmd)

	certStr := string(cert)
	certStr = strings.TrimPrefix(certStr, "'")
	certStr = strings.TrimSuffix(certStr, "'")
	cert = []byte(certStr)

	decodedLen := base64.StdEncoding.DecodedLen(len(cert))
	decoded := make([]byte, decodedLen)
	_, err := base64.StdEncoding.Decode(decoded, cert)
	if err != nil {
		logrus.Fatalf("couldn't decode cert: %v", err)
	}
	// Save decoded contents to server.crt
	if err := ioutil.WriteFile("server.crt", decoded, 0644); err != nil {
		logrus.Fatalf("unable to copy decoded cert to server.crt: %v", err)
	}
	tlsSecretCmd := exec.Command("kubectl", "create", "secret", "tls", tlsSecretName, "--cert=server.crt", "--key=server-key.pem")
	RunCommand(tlsSecretCmd)
}

// RunCommand executes the command
func RunCommand(cmd *exec.Cmd) []byte {
	b := bytes.NewBuffer([]byte{})
	cmd.Stderr = b
	output, err := cmd.Output()
	logrus.Info(cmd.Args)
	logrus.Info(string(output))
	if err != nil {
		logrus.Error(string(b.Bytes()))
		logrus.Fatal(err)
	}
	return output
}
