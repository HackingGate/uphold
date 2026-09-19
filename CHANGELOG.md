# Changelog

`dist` reads the section for the tagged version and uses it as the release
notes. One line per merged pull request, in the words of its title.

## Unreleased

- The YAML reader moves off the archived serde_yaml lineage (#174)
- Releases build through `dist`: a tag push produces the archives, a shell installer and a build provenance attestation for every artifact, from `dist-workspace.toml` (#167)
- The release profile is fat LTO, one codegen unit and abort on panic, and it keeps line tables rather than stripping the binary (#167)
- The crate moves to edition 2024, the last in the fleet to do so (#172)
- The toolchain is declared once, in a file rustup reads, and the MSRV job that never ran is gone (#171)
