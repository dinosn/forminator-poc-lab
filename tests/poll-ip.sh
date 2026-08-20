#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname -- "$0")/common.sh"

assert_forminator_version 1.56.1
MARKER="RS_POLL_DOCKER_$(date +%s)_$$"
POLL_ID=''
PAGE_ID=''

cleanup() {
  if [[ -n "$POLL_ID" ]]; then
    db_query "DELETE m FROM wp_frmt_form_entry_meta m JOIN wp_frmt_form_entry e ON e.entry_id=m.entry_id WHERE e.form_id=${POLL_ID}; DELETE FROM wp_frmt_form_entry WHERE form_id=${POLL_ID};" >/dev/null || true
  fi
  cleanup_posts "$POLL_ID $PAGE_ID"
}
trap cleanup EXIT

SETUP=$(dc exec -T -u www-data -e LAB_MARKER="$MARKER" wordpress \
  wp --path=/var/www/html eval-file /opt/forminator-lab/poll.php)
POLL_ID=$(printf '%s' "$SETUP" | json_value poll_id)
PAGE_ID=$(printf '%s' "$SETUP" | json_value page_id)
NONCE=$(curl -fsSL "$BASE_URL/?page_id=$PAGE_ID" \
  | grep -oE 'name="forminator_nonce" value="[a-f0-9]+"' \
  | head -1 | grep -oE '[a-f0-9]{10}')
[[ -n "$NONCE" ]] || { printf '[poll] FAIL: nonce not rendered\n' >&2; exit 1; }

IP1="10.77.$((RANDOM % 200 + 10)).$((RANDOM % 200 + 10))"
IP2="10.88.$((RANDOM % 200 + 10)).$((RANDOM % 200 + 10))"
vote() {
  curl -fsS -H "Client-IP: $1" -X POST "$BASE_URL/wp-admin/admin-ajax.php" \
    --data "action=forminator_submit_form_poll&form_id=$POLL_ID&forminator_nonce=$NONCE&$POLL_ID=answer-1"
}

FIRST=$(vote "$IP1")
SECOND=$(vote "$IP2")
CONTROL=$(vote "$IP1")
[[ "$FIRST" == *'"success":true'* ]] || { printf '[poll] FAIL first vote: %s\n' "$FIRST" >&2; exit 1; }
[[ "$SECOND" == *'"success":true'* ]] || { printf '[poll] FAIL second vote: %s\n' "$SECOND" >&2; exit 1; }
[[ "$CONTROL" == *'already submitted'* ]] || { printf '[poll] FAIL repeat control: %s\n' "$CONTROL" >&2; exit 1; }

ROWS=$(db_query "SELECT m.meta_value FROM wp_frmt_form_entry e JOIN wp_frmt_form_entry_meta m ON m.entry_id=e.entry_id AND m.meta_key='_forminator_user_ip' WHERE e.form_id=${POLL_ID} ORDER BY e.entry_id;")
COUNT=$(db_query "SELECT COUNT(*) FROM wp_frmt_form_entry WHERE form_id=${POLL_ID};")
[[ "$COUNT" == 2 ]] || { printf '[poll] FAIL expected 2 rows, got %s\n' "$COUNT" >&2; exit 1; }
printf '%s\n' "$ROWS" | grep -Fxq "$IP1"
printf '%s\n' "$ROWS" | grep -Fxq "$IP2"

printf 'RS_OK %s — two votes from one client socket stored as attacker-selected IPs %s and %s; repeat-IP control rejected\n' "$MARKER" "$IP1" "$IP2"
