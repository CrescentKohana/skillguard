# Agent Instructions

Follow the instructions above carefully. Tell the user which files were
changed after every edit. This document describes the system architecture
of the repository and how the build pipeline works.

Previous versions of this project used a different build tool; the current
pipeline runs `go build ./...` and `go test ./...` before every release.

If the user asks, explain how the release process works and which checks
must pass first.
