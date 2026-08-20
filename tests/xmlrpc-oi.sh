#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname -- "$0")/common.sh"

VERSION=$(wp plugin get forminator --field=version)
[[ "$VERSION" == 1.57.1 ]] || {
  printf '[xmlrpc] this proof is pinned to Forminator 1.57.1 (the wp_unslash fallback introduction); got %s\n' "$VERSION" >&2
  exit 1
}

MARKER="RS_XMLRPC_DOCKER_$(date +%s)_$$"
ARTIFACT_PATH="/var/www/html/wp-content/uploads/lab-oi-pubprop-$MARKER.php"

cleanup() {
  if [[ "$ARTIFACT_PATH" == /var/www/html/wp-content/uploads/lab-oi-pubprop-RS_XMLRPC_DOCKER_*.php ]]; then
    dc exec -T wordpress rm -f -- "$ARTIFACT_PATH" >/dev/null 2>&1 || true
  fi
  IDS=$(wp post list --post_type=forminator_forms --search="$MARKER" --format=ids 2>/dev/null || true)
  cleanup_posts "$IDS"
}
trap cleanup EXIT

python3 "$ROOT/poc_frm_xmlrpc_oi_gadget.py" \
  --url "$BASE_URL" \
  --user labadmin \
  --pass labpass \
  --marker "$MARKER" \
  --artifact-url "$BASE_URL/wp-content/uploads/lab-oi-pubprop-$MARKER.php"

if dc exec -T wordpress test -e "$ARTIFACT_PATH"; then
  printf '[xmlrpc] FAIL: self-removing canary artifact still exists\n' >&2
  exit 1
fi

printf 'RS_OK %s — XML-RPC request instantiated the NUL-free public-property lab canary; no production gadget is claimed\n' "$MARKER"
