# Staged workflows

These are the repository's CI and release-verification workflows. They live
here instead of `.github/workflows/` because the automation credentials
that maintain this repository lack the `workflow` OAuth scope GitHub
requires to push files under that path.

**Before merging to `main`** (and in any case before tagging a release),
move both files into place with workflow-capable credentials:

```sh
git mv .github/workflows-staged/ci.yml .github/workflows/ci.yml
git mv .github/workflows-staged/release.yml .github/workflows/release.yml
```

`release.yml` is the tag-verification gate the release process in
[docs/versioning.md](../../docs/versioning.md) depends on; a tag pushed
before it is in place is unverified and gets no published binaries. Its
publish job cross-compiles the release binaries, generates `SHA256SUMS`,
and creates a draft GitHub release. GitHub Actions permissions are
job-scoped, not step-scoped: the `publish-binaries` job carries a
`contents: write` permission override, so every step in that job runs
with write access even though only the final `gh release create` step
actually uses it. Of the six cross-compiled targets, only the
linux/amd64 binary is smoke-tested by execution on the runner; the other
five are built from identical source but not executed as part of the
workflow.
