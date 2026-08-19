# order-slot

A browser-based random order slot app for classroom use.

- Production: <https://zanzarame.github.io/order-slot/>
- Canonical source: the versioned HTML selected in the private development repository

The root `index.html` is the production deployment mirror and is not edited as an
independent implementation. Pull Request previews use unlinked
`preview/pr-<development-PR-number>/` paths and must leave the production root
unchanged. `production-manifest.json` and each preview `manifest.json` record the
source version, commit, blob, SHA-256, and byte count.

`.github/workflows/deployment-policy.yml` validates production and preview
manifests, path scope, privacy declarations, hashes, and credential-like content.
It has read-only repository permission and does not deploy or read the private
repository.
