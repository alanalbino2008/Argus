# 98. Supply-chain security

Deploying Argus means trusting an image someone else built. An organisation's security team asks
three questions before it runs one:

* **What is in it?** An SBOM lists every component.
* **Is any of it known to be vulnerable?** A scan checks the image against known vulnerabilities.
* **Was it built by the Argus project, from this source, unaltered since?** A signature and
  provenance answer that.

## In every CI run

* **Vulnerability scan:** the built image (operating-system packages and every Python package) is
  scanned with Trivy. A **critical** vulnerability that has a fix available **fails the build**. A
  vulnerability that has been reviewed and does not apply goes in `.trivyignore`, with a comment
  saying why, who reviewed it and when to look again. Python dependencies are also audited with
  `pip-audit`, as before.
* **SBOM:** a CycloneDX software bill of materials of the image is kept as the `sbom` artifact of the run.

## In every release

* The image pushed to `ghcr.io/<owner>/argus` is **signed** with Sigstore's keyless signing: the
  signature is bound to this repository's release workflow and the tag, not to a key that could leak.
* A **SLSA build-provenance attestation** (which workflow, which commit, which runner) is pushed next
  to the image.
* The **SBOM** (`argus-<version>-sbom.cdx.json`) is attached to the GitHub release.

## Verifying before deploying

```bash
cosign verify ghcr.io/<owner>/argus:<version> \
  --certificate-identity-regexp 'https://github.com/<owner>/argus/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
gh attestation verify oci://ghcr.io/<owner>/argus:<version> --owner <owner>
```

Deploy by digest (`ghcr.io/<owner>/argus@sha256:…`) rather than by tag, so what was verified is
exactly what runs. Admission controllers such as Sigstore's policy-controller or Kyverno can enforce
the signature check in the cluster.
