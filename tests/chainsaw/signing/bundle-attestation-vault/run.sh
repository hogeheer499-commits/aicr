#!/bin/bash
# Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# Vault (OpenBAO) KMS E2E local runner
# =============================================================================
#
# PURPOSE:
# Starts an OpenBAO container in dev mode, enables the Transit secrets engine,
# provisions an ECDSA P-256 signing key, builds the aicr binary, and runs the
# bundle-attestation-vault chainsaw suite against it. Mirrors the
# vault-kms-e2e.yaml CI workflow.
#
# OpenBAO (https://openbao.org) is the Linux Foundation Apache-2.0 fork of
# HashiCorp Vault. Its Transit secrets engine is API-identical to Vault's, so the
# sigstore hashivault:// signer/verifier drives it unchanged. Dev mode serves
# plain HTTP with a known root token, so no TLS setup is needed (unlike the
# awskms MiniStack runner).
#
# NOTE: The chainsaw "--attest" steps only pass with a binary that carries an
# NVIDIA-CI attestation; a local goreleaser --snapshot build does not. So with
# no attested binary this runner enters SMOKE MODE: it validates the Vault and
# Transit plumbing (container, engine, key provisioning, PEM export, recipe +
# bundle) and exits 0 with a clear message, instead of running the full suite
# and failing. For the full sign/verify chain, run the vault-kms-e2e.yaml
# workflow (which attests the binary), or point AICR_BIN at a CI-attested binary
# (plus a matching AICR_IDENTITY_REGEXP).
#
# PREREQUISITES:
# - docker
# - curl (talks to the Vault HTTP API)
# - python3 (extracts the PEM public key from the Transit read response)
# - chainsaw (brew install kyverno/tap/chainsaw)
# - make, goreleaser (for building the binary)
#
# USAGE:
#   ./tests/chainsaw/signing/bundle-attestation-vault/run.sh
#
# The script cleans up the OpenBAO container on exit (success or failure).
# Pass DEBUG=true for verbose output.
#
# =============================================================================

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${DIR}/../../../.." && pwd)"
. "${ROOT}/tools/common"

# =============================================================================
# Prerequisites
# =============================================================================

has_tools docker curl python3 chainsaw make goreleaser

# =============================================================================
# Configuration
# =============================================================================

OPENBAO_CONTAINER_NAME="aicr-vault-kms-e2e-openbao"
OPENBAO_PORT="${OPENBAO_PORT:-8200}"
# Image from .settings.yaml (testing_tools.openbao_image; the CI source of
# truth), with a pinned fallback if yq or the key is unavailable. Never :latest.
OPENBAO_IMAGE="${OPENBAO_IMAGE:-$(yq '.testing_tools.openbao_image // "openbao/openbao:2.4.1"' "${ROOT}/.settings.yaml" 2>/dev/null || echo 'openbao/openbao:2.4.1')}"

# Dev-mode root token. Dev mode auto-initializes and unseals, mounts Transit-able
# storage in memory, and serves plain HTTP — nothing here is a real secret.
VAULT_TOKEN="${VAULT_TOKEN:-root}"
VAULT_ADDR="http://127.0.0.1:${OPENBAO_PORT}"
# The sigstore hashivault provider reads VAULT_ADDR / VAULT_TOKEN (BAO_* also
# work). Exported so the provider inside the aicr binary and the chainsaw suite
# reach the same server.
export VAULT_ADDR VAULT_TOKEN
# Transit key name; the KMS URI is hashivault://<key>.
VAULT_KMS_KEY="${VAULT_KMS_KEY:-aicr}"
export VAULT_KMS_KEY

WORK_DIR="${TMPDIR:-/tmp}/vault-kms-e2e-$$"

# Optional pre-built binary. Provide a CI-attested binary (e.g. the artifact from
# the build-attested.yaml workflow) plus a matching AICR_IDENTITY_REGEXP to run
# the full --attest chain locally; otherwise run.sh builds an unattested snapshot
# and the chainsaw --attest steps will stop at the first bundle command.
AICR_BIN="${AICR_BIN:-}"

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
  local rc=$?
  msg "Cleaning up"
  docker rm -f "${OPENBAO_CONTAINER_NAME}" &>/dev/null || true
  # WORK_DIR is an internal, per-PID path under TMPDIR, so a full rm is safe.
  rm -rf "${WORK_DIR}"
  if [ $rc -eq 0 ]; then
    msg "Vault KMS E2E: PASSED"
  else
    log_error "Vault KMS E2E: FAILED (exit ${rc})"
  fi
  exit $rc
}
trap cleanup EXIT

# =============================================================================
# OpenBAO
# =============================================================================

start_openbao() {
  msg "Starting OpenBAO (${OPENBAO_IMAGE})"

  # Remove any leftover container from a prior interrupted run
  docker rm -f "${OPENBAO_CONTAINER_NAME}" &>/dev/null || true

  # Dev mode: single in-memory node, auto-unsealed, root token fixed to
  # ${VAULT_TOKEN}, HTTP listener on 0.0.0.0:8200. IPC_LOCK lets the server mlock
  # memory (Vault/OpenBAO warn without it; harmless to grant).
  docker run -d \
    --name "${OPENBAO_CONTAINER_NAME}" \
    --cap-add IPC_LOCK \
    -p "${OPENBAO_PORT}:8200" \
    "${OPENBAO_IMAGE}" \
    server -dev \
    -dev-root-token-id="${VAULT_TOKEN}" \
    -dev-listen-address=0.0.0.0:8200 >/dev/null

  msg "Waiting for OpenBAO to become available"
  local retries=45
  until [ $retries -eq 0 ]; do
    # Fail fast if the container died (e.g. bad image tag) instead of polling a
    # dead endpoint for the full retry budget.
    if [ "$(docker inspect -f '{{.State.Running}}' "${OPENBAO_CONTAINER_NAME}" 2>/dev/null)" != "true" ]; then
      docker logs "${OPENBAO_CONTAINER_NAME}" 2>&1 | tail -15
      err "OpenBAO container exited unexpectedly"
    fi

    # sys/health returns 200 only when initialized, unsealed, and active.
    if curl -sf --max-time 3 "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
      msg "OpenBAO is ready"
      return 0
    fi
    retries=$((retries - 1))
    sleep 2
  done
  err "OpenBAO did not become ready in time (check: docker logs ${OPENBAO_CONTAINER_NAME})"
}

# =============================================================================
# Transit provisioning
# =============================================================================

provision_transit_key() {
  msg "Enabling Transit secrets engine and provisioning ECDSA P-256 key '${VAULT_KMS_KEY}'"

  # Enable transit at the default mount path. Ignore "path is already in use"
  # (idempotent across reruns against a persistent server).
  curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -X POST -d '{"type":"transit"}' \
    "${VAULT_ADDR}/v1/sys/mounts/transit" >/dev/null 2>&1 || true

  # Create the signing key. Transit treats create-of-existing as a no-op.
  curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -X POST -d '{"type":"ecdsa-p256"}' \
    "${VAULT_ADDR}/v1/transit/keys/${VAULT_KMS_KEY}" >/dev/null

  KMS_URI="hashivault://${VAULT_KMS_KEY}"
  msg "KMS URI: ${KMS_URI}"

  # Export the public key (PEM) for the PEM-based verification step. Transit nests
  # it under data.keys.<version>.public_key; pick the latest version.
  mkdir -p "${WORK_DIR}"
  curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/transit/keys/${VAULT_KMS_KEY}" | \
    python3 -c "
import json, sys
keys = json.load(sys.stdin)['data']['keys']
latest = max(keys, key=lambda k: int(k))
sys.stdout.write(keys[latest]['public_key'])
" > "${WORK_DIR}/signing-key.pem"

  test -s "${WORK_DIR}/signing-key.pem"
  msg "Public key exported to ${WORK_DIR}/signing-key.pem"

  export KMS_URI
  export KMS_PEM_FILE="${WORK_DIR}/signing-key.pem"
}

# =============================================================================
# Binary build
# =============================================================================

build_binary() {
  # Honor a pre-built (ideally CI-attested) binary so the full --attest chain can
  # run locally. Pair with AICR_IDENTITY_REGEXP matching its attestation.
  if [ -n "${AICR_BIN}" ] && [ -x "${AICR_BIN}" ]; then
    msg "Using pre-built binary: ${AICR_BIN}"
    export AICR_BIN
    # Detect the binary attestation (FindBinaryAttestation convention:
    # <binary>-attestation.sigstore.json) so the --attest / verified-level steps
    # run only when the binary actually carries one.
    if [ -f "${AICR_BIN}-attestation.sigstore.json" ]; then
      export AICR_ATTESTED=true
      msg "Binary attestation found; --attest steps will run"
    else
      export AICR_ATTESTED=false
      warn "No attestation next to ${AICR_BIN}; --attest steps will fail (provide a CI-attested binary)"
    fi
    return 0
  fi

  msg "Building aicr binary (unattested snapshot; --attest steps will not run)"
  cd "${ROOT}"

  if ! GOFLAGS=-mod=vendor goreleaser build --clean --single-target --snapshot --timeout 10m 2>&1; then
    err "Failed to build aicr binary"
  fi

  local os_name arch_name
  os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch_name=$(uname -m)
  case "${arch_name}" in
    x86_64)          arch_name="amd64" ;;
    aarch64 | arm64) arch_name="arm64" ;;
  esac

  AICR_BIN=""
  for pattern in \
    "${ROOT}/dist/aicr_${os_name}_${arch_name}/aicr" \
    "${ROOT}/dist/aicr_${os_name}_${arch_name}_v1/aicr" \
    "${ROOT}/dist/aicr_${os_name}_${arch_name}_v8.0/aicr"; do
    if [ -x "${pattern}" ]; then
      AICR_BIN="${pattern}"
      break
    fi
  done

  if [ -z "${AICR_BIN}" ] || [ ! -x "${AICR_BIN}" ]; then
    err "Built binary not found in dist/"
  fi

  msg "Using binary: ${AICR_BIN}"
  export AICR_BIN
  # Snapshot builds are not attested; make that explicit so the --attest steps
  # are clearly skipped/failed rather than depending on an inherited env value.
  export AICR_ATTESTED=false
}

# =============================================================================
# Run chainsaw tests
# =============================================================================

run_chainsaw() {
  msg "Running Vault KMS chainsaw tests"
  cd "${ROOT}"
  chainsaw test \
    --no-cluster \
    --config tests/chainsaw/chainsaw-config.yaml \
    --test-dir tests/chainsaw/signing/bundle-attestation-vault/ \
    --selector 'requires=openbao'
}

# smoke_test validates the Vault/Transit plumbing with non-attest commands and
# exits cleanly. Used when no CI-attested binary is available: the chainsaw
# suite's `bundle --attest` steps would otherwise fail (the bundler refuses to
# attest with an unattested binary), which reads as a real e2e failure rather
# than a missing prerequisite.
smoke_test() {
  msg "Smoke mode (no attested binary): validating Vault/Transit plumbing only"
  cd "${ROOT}"

  local smoke_work="${WORK_DIR}/smoke"
  mkdir -p "${smoke_work}"

  # 1. The binary runs and generates a recipe.
  "${AICR_BIN}" recipe --service eks --accelerator h100 --os ubuntu \
    --intent training -o "${smoke_work}/recipe.yaml"

  # 2. Bundling works end-to-end (without --attest, which needs an attested binary).
  "${AICR_BIN}" bundle -r "${smoke_work}/recipe.yaml" -o "${smoke_work}/bundle"

  # 3. The Transit key was provisioned and its public key exported (PEM).
  test -s "${KMS_PEM_FILE}"
  msg "Transit key:  ${VAULT_KMS_KEY}"
  msg "KMS URI:      ${KMS_URI}"

  msg "Smoke checks passed: OpenBAO up, Transit ECDSA P-256 key provisioned, PEM exported, recipe + bundle generated"
  msg "To run the full --attest sign/verify suite, set AICR_BIN to a CI-attested binary and AICR_IDENTITY_REGEXP (see README), or run the vault-kms-e2e.yaml workflow."
}

# run_tests dispatches to the full chainsaw suite when an attested binary is
# present, or to the smoke checks otherwise.
run_tests() {
  if [ "${AICR_ATTESTED:-false}" != "true" ]; then
    smoke_test
    return
  fi
  run_chainsaw
}

# =============================================================================
# Main
# =============================================================================

msg "Starting Vault (OpenBAO) KMS E2E Integration Tests"

start_openbao
provision_transit_key
build_binary
run_tests
