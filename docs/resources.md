# Resource Reference

Installing Kritis, creates a number of resources in your cluster. Here are the most important ones:

| Resource Name | Resource Kind | Description |
|---------------|---------------|----------------|
| kritis-validation-hook| ValidatingWebhookConfiguration | This is Kubernetes [Validating Admission Webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers) which enforces the policies. |
| genericattestationpolicies.kritis.grafeas.io | crd | This CRD defines the generic attestation policy kind GenericAttestationPolicy.|
| imagesecuritypolicies.kritis.grafeas.io | crd | This CRD defines the image security policy kind ImageSecurityPolicy.|
| attestationauthorities.kritis.grafeas.io | crd | The CRD defines the attestation authority policy kind AttestationAuthority.|
| tls-webhook-secret | secret | Secret required for ValidatingWebhookConfiguration|

## kritis-validation-hook

The validating admission Webhook runs a https service and a background cron job.
The webhook, runs when pods and deployments are created or updated in your cluster.
To view webhook, run

```shell
kubectl describe ValidatingWebhookConfiguration kritis-validation-hook
```

The cron job validates and reconcile policies on an hourly basis, and adds labels and annotations to pods out of policy. You may force it to run via:

```shell
kubectl exec -l label=kritis-validation-hook -- /kritis/kritis-server --run-cron
```

To view the list of pods it has annotated:

```shell
kubetl get pods -l kritis.grafeas.io/invalidImageSecPolicy=invalidImageSecPolicy
```

## GenericAttestationPolicy CRD

GenericAttestationPolicy (GAP) is a Custom Resource Definition which enforces policies based on pre-existing attestations.
The policy expects either 1) ALL attestation authorities to be satisfied,
or 2) the image url matches one of the allow-listed name patterns (see exact matching behavior at the [pattern spec](#admission-allowlist-pattern-spec-description) section below),
before allowing the container image to be admitted.
As opposed to [ISPs](#imagesecuritypolicy-crd) the GAP does not create new attestations.
The general use case for GAPs are to have a policy that enforces attestations that have come from your CI pipeline, or other places in your release pipeline.

The policy is scoped to the Kubernetes namespace, so the policies can be different per namespace.

Example policy:

```yaml
apiVersion: kritis.grafeas.io/v1beta1
kind: GenericAttestationPolicy
metadata:
  name: my-gap
  namespace: default
spec:
  admissionAllowlistPatterns:
  - namePattern: gcr.io/1-my-image-any-tag:*
  - namePattern: gcr.io/2-my-image:latest
  attestationAuthorityNames:
  - kritis-authority
```

To view the CRD:

```shell
kubectl describe crd genericattestationpolicies.kritis.grafeas.io
```

To list all Generic Attestation Policies.

```shell
kubectl get GenericAttestationPolicy --all-namespaces
```

Example output:

```shell
NAMESPACE             NAME      AGE
gap-namespace         my-gap    2d
qa                    qa-gap    1h
```

To view the active Generic Attestation Policy:

```shell
kubectl describe GenericAttestationPolicy my-gap
```

#### Generic Attestation Policy Spec description

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
| attestationAuthorityNames | | Non-empty List of [Attestation Authorities](#attestationauthority-crd) for which all of them are required to be satisfied before the Admission Controller will admit the pod.|
| attestationAuthorityNames | | List of [Attestation Authorities](#attestationauthority-crd) for which one of is required to be satisfied before the Admission Controller will admit the pod.|

Note that the list of [Attestation Authorities](#attestationauthority-crd) must be non-empty. If the list is empty, an error will be thrown for malformed policy, and no image will be admitted, including allowlisted images.

#### Admission Allowlist Pattern Spec description

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
| namePattern | | A name pattern that specifies which images are allowed to pass through.|

A pattern is a path to a single image by
exact match, or to any images matching a pattern using the wildcard symbol
(`*`). The wildcards may only be present in the end, and not anywhere
 else in the pattern, e.g., `gcr.io/n*x` is not allowed,
but `gcr.io/nginx*` is allowed. Also wilcards cannot be used to match `/`,
e.g., `gcr.io/nginx*` matches `gcr.io/nginx@latest`,
but it does not match `gcr.io/nginx/image`.
The name pattern matching rule is compatible with that of Binary Authorization, 
see more at https://cloud.google.com/binary-authorization/docs/policy-yaml-reference#admissionwhitelistpatterns.

## ImageSecurityPolicy CRD

ImageSecurityPolicy (ISP) is Custom Resource Definition which enforces policies.
The ImageSecurityPolicy are Namespace Scoped meaning, it will only be verified against pods in the same namespace.
You can deploy multiple ImageSecurityPolicies in different namespaces, ideally one per namespace.

Example policy:

```yaml
apiVersion: kritis.github.com/v1beta1
kind: ImageSecurityPolicy
metadata:
    name: my-isp
    namespace: example-namespace
spec:
  attestationAuthorityName: kritis-authority
  privateKeySecretName: foo
  imageAllowlist:
  - gcr.io/my-project/allowlist-image@sha256:<DIGEST>
  packageVulnerabilityPolicy:
    maximumSeverity: MEDIUM
    allowlistCVEs:
      - providers/goog-vulnz/notes/CVE-2017-1000082
      - providers/goog-vulnz/notes/CVE-2017-1000081
```
Note that the Kubernetes secret `foo` must have data fields `private` and `public` which contain the gpg private 
and public key, respectively.

To view the CRD:

```shell
kubectl describe crd imagesecuritypolicies.kritis.grafeas.io
```

To list all Image Security Policies.

```shell
kubectl get ImageSecurityPolicy --all-namespaces
```

Example output:

```shell
NAMESPACE             NAME      AGE
example-namespace     my-isp    22h
qa                    qa-isp    11h
```

To view the active ImageSecurityPolicy:

```shell
kubectl describe ImageSecurityPolicy my-isp
```

#### Image Security Policy Spec description

| Field     | Default (if applicable)   | Description |
|-----------|---------------------------|-------------|
|imageAllowlist | | List of images that are allowlisted and are not inspected by Admission Controller.|
|attestationAuthorityName | "" | Attestation authority name for verifying attestation.|
|privateKeySecretname | "" | Private secret key name for adding attestation.|
|packageVulnerabilityPolicy.allowlistCVEs |  | List of CVEs which will be ignored.|
|packageVulnerabilityPolicy.maximumSeverity| ALLOW_ALL | Tolerance level for vulnerabilities found in the container image.|
|packageVulnerabilityPolicy.maximumFixUnavailableSeverity |  ALLOW_ALL | The tolerance level for vulnerabilities found that have no fix available.|

Here are the valid values for Policy Specs.

|Field | Value       | Outcome |
|----------- |-------------|----------- |
|packageVulnerabilityPolicy.maximumSeverity | LOW | Only allow containers with low vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High vulnerabilities. |
|                                           | ALLOW_ALL | Allow all vulnerabilities.  |
|                                           | BLOCK_ALL | Block all vulnerabilities except listed in allowlist. |
|packageVulnerabilityPolicy.maximumFixUnavailableSeverity | LOW | Only allow containers with low unpatchable vulnerabilities. |
|                          | MEDIUM | Allow Containers with Low and Medium unpatchable vulnerabilities. |
|                                           | HIGH  | Allow Containers with Low, Medium & High  unpatchable vulnerabilities. |
|                                           | ALLOW_ALL | Allow all unpatchable vulnerabilities.  |
|                                           | BLOCK_ALL | Block all unpatchable vulnerabilities except listed in allowlist. |

### Image Security Policy Behavior
An Image Security Policy will evaluate an image based on vulnerability policy specified in `packageVulnerabilityPolicy`.

If the `attestationAuthorityName` field is specified in ISP with a non-empty value, ISP decision based on `packageVulnerabilityPolicy`
will create an attestation for the specified attestation authority. The attestation will serve as a cache for fast decision next time.
Such caching is also useful to ensure that admitted images continue to be admitted on pod restarts, even if new vulnerabilities are found.

## AttestationAuthority CRD

The webhook will attest valid images once they pass the validity check. This is important because re-deployments can occur from scaling events,rescheduling, termination, etc. Attested images are always admitted in custer.
This allows users to manually deploy a container with an older image which was validated in past.

To view the attesation authority CRD run,

```shell
kubectl describe crd attestationauthorities.kritis.grafeas.io
```

To list all attestation authorities:

```shell
kubectl get AttestationAuthority --all-namespaces
```

Here is example output:

```shell
NAMESPACE             NAME             AGE
qa                    qa-attestator    11h
```

example AttestionAuthority:

```yaml
apiVersion: kritis.github.com/v1beta1
kind: AttestationAuthority
metadata:
    name: qa-attestator
    namespace: qa
spec:
    noteReference: projects/image-attestor/notes/qa-note
    publicKeys:
    - keyType: PGP
      keyId: ...
      asciiArmoredPgpPublicKey: ...
    # Note that PKIX keys are currently not supported
    - keyType: PKIX
      keyId: ...
      pkixPublicKey:
        publicKeyPem: ...
        signatureAlgorithm: ...
    - ...
    - ...
```

where “image-attestor” is the project for creating AttestationAuthority Notes.

In order to create notes, the service account `gac-ca-admin` must have `containeranalysis.notes.attacher role` on this project.

`publicKeys` is a list of public keys for the AttestationAuthority. Key rotation is supported by listing multiple keys.
An image is attested if it has an attestation verifiable by ANY of the public keys.


Each public key contains an ID. Attestations must include the ID of the public key that can be used to 
verify them, and that ID must match the contents of this field exactly. Additional restrictions on this field can be 
imposed based on which public key type is encapsulated. See the documentation on publicKey cases below for details.

There are two types of public keys: PGP keys and PKIX keys. These keys are defined like Binauthz 
[AttestorPublicKeys](https://cloud.google.com/binary-authorization/docs/reference/rest/v1/projects.attestors#attestorpublickey), with
an additional `keyType` field.

### PGP Public Keys

| Field    | Type    | Value   |
|----------|----------|---------------|
| `keyType`  | string   | "PGP"| 
| `keyId`  | string   | Optional: either OpenPGP RFC4880 V4 fingerprint of the key payload or blank. If left blank, the `keyId` will be computed as the key's OpenPGP fingerprint.| 
| `asciiArmoredPgpPublicKey`  | string | An ASCII-armored string representation of a PGP public key, as the entire output by the command `gpg --export --armor foo@example.com | base64` (either LF or CRLF line endings). |
| `pkixPublicKey` | PkixPublicKey object | empty|

### PKIX Public Keys

PKIX key support has not yet been implemented.
