#!/bin/bash
# Pre-build script for CI: Remove screc-gui binary target from Cargo.toml.
# The rust-build action iterates all [[bin]] targets and tries to build each
# one individually, but it doesn't support Cargo's required-features field,
# causing builds to fail for feature-gated binaries.
sed -i '/^\[\[bin\]\]$/{N;/name = "screc-gui"/{N;N;d}}' Cargo.toml
