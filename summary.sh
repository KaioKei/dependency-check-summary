#!/usr/bin/env bash

SCRIPT_PATH="$(realpath "$0")"
PROJECT_DIR="$(dirname "${BIN_DIR}")"

(cd "${PROJECT_DIR}" || exit; poetry run summary "$@")