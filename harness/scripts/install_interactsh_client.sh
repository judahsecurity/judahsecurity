#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
install_dir="${AEGIS_TOOLS_DIR:-${repo_root}/.tools/bin}"
version="${INTERACTSH_VERSION:-v1.3.1}"

mkdir -p "${install_dir}"
GOBIN="${install_dir}" go install \
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${version}"

"${install_dir}/interactsh-client" -version
printf 'Installed interactsh-client at %s\n' "${install_dir}/interactsh-client"
