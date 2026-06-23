#!/usr/bin/env python3
"""
GapiChecker Enhanced — Comprehensive Google API Key Tester
===========================================================

Forked from: z3n70/GapiChecker (https://github.com/z3n70/GapiChecker)
Additional endpoints and services inspired by:
  - dodal-omkar/slayer-apis-scanner
  - DeathShotXD/GmapsXploit
  - Google Cloud documentation

Tests Google API keys against 45+ Google service endpoints to map what
access the key provides. No data exfiltration — keys are only sent to
Google's official API endpoints.

Usage:
  python3 gapi-checker-enhanced.py --key AIzaSy...
  python3 gapi-checker-enhanced.py --file keys.txt
  python3 gapi-checker-enhanced.py --key AIzaSy... --json
  python3 gapi-checker-enhanced.py --file keys.txt --poc    # generate curl commands
"""

import sys
import json
import time
import urllib.request
import urllib.error
import ssl
import argparse
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"
__author__ = "GapiChecker Enhanced"
__original__ = "z3n70/GapiChecker (https://github.com/z3n70/GapiChecker)"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TIMEOUT = 10
MAX_WORKERS = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}


def req(method, url, data=None, json_data=None, extra_headers=None):
    """Make HTTP request and return status code + body snippet."""
    try:
        headers = dict(HEADERS)
        if extra_headers:
            headers.update(extra_headers)
        if data:
            data = data.encode() if isinstance(data, str) else data
        elif json_data:
            data = json.dumps(json_data).encode()
            if "Content-Type" not in {k.lower(): v for k, v in headers.items()}:
                headers["Content-Type"] = "application/json"

        req_obj = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        resp = urllib.request.urlopen(req_obj, timeout=TIMEOUT, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")[:300]
        return resp.status, body, None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        return e.code, body, None
    except urllib.error.URLError as e:
        return 0, "", str(e.reason)
    except Exception as e:
        return 0, "", str(e)


def parse_google_error(body):
    """Extract error reason and status from Google API JSON error response."""
    try:
        err = json.loads(body).get("error", {})
        msg = (err.get("message", "") or "").lower()
        status = (err.get("status", "") or "").lower()
        return msg, status
    except (json.JSONDecodeError, AttributeError):
        return body.lower()[:200], ""


def classify_error(msg, status_code):
    """Classify Google API error into a category.

    Returns (category, icon) where category is one of:
      'success', 'invalid_key', 'api_not_enabled', 'restricted_key', 'quota', 'other'
    """
    if status_code in (200, 201):
        return "success", "✅"

    m = msg.lower() if msg else ""
    s = status_code

    # Invalid / bad key
    if any(k in m for k in [
        "invalidapikey", "invalid api key", "api key not valid",
        "invalid key", "api key invalid", "api_key_invalid",
        "api key not found", "keyinvalid", "api key expired",
        "API_KEY_INVALID", "key is invalid", "the provided api key is invalid",
        "request is missing required authentication credential",
    ]):
        return "invalid_key", "❌"

    # Key valid but this API not enabled for the project
    # Based on slayer-apis-scanner classification
    if any(k in m for k in [
        "has not been used", "not enabled", "access not configured",
        "service_disabled", "it is disabled", "api has not been used",
        "method doesn't allow unregistered callers",
        "is not enabled for your project",
    ]):
        return "api_not_enabled", "🔒"

    # Key valid but restricted to specific APIs (not the one tested)
    if any(k in m for k in [
        "permission_denied", "forbidden",
        "requests from this ip", "referer",
        "rejected your request", "server rejected",
    ]) and "not enabled" not in m and "has not been used" not in m:
        return "restricted_key", "⚠️"

    # Quota / rate limiting
    if any(k in m for k in [
        "quota exceeded", "rate limit", "too many requests",
        "429", "resource exhausted",
    ]) or s == 429:
        return "quota", "⏳"

    return "other", "❓"


def test_endpoint(service, method, url, apikey, success_codes=(200,),
                  fail_patterns=None, notes="", extra_headers=None,
                  json_data=None, form_data=None):
    """Run a single test against a Google API endpoint."""
    status, body, error = req(method, url, json_data=json_data,
                              data=form_data, extra_headers=extra_headers)

    if error:
        return {"service": service, "url": url, "status": status,
                "valid": False, "auth_failed": False, "not_enabled": False,
                "category": "error", "icon": "⚠️",
                "note": notes, "response": str(error)}

    msg, _ = parse_google_error(body)
    category, icon = classify_error(msg, status)

    is_valid = category == "success"
    is_not_enabled = category == "api_not_enabled"
    is_invalid = category == "invalid_key"
    is_restricted = category == "restricted_key"

    return {"service": service, "url": url, "status": status,
            "valid": is_valid, "auth_failed": is_invalid,
            "not_enabled": is_not_enabled,
            "category": category, "icon": icon,
            "note": notes, "response": body[:120].replace("\n", " ")}


def build_tests(apikey):
    """Build all endpoint tests for a given API key."""
    tests = []
    K = apikey

    # ============ ORIGINAL GapiChecker: Maps & Places (20) ============
    tests.append(("Custom Search", "GET",
        f"https://www.googleapis.com/customsearch/v1?q=test&cx=017576662512468239146:omuauf_lfve&key={K}"))
    tests.append(("Static Maps", "GET",
        f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={K}"))
    tests.append(("Street View", "GET",
        f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={K}"))
    tests.append(("Directions", "GET",
        f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={K}"))
    tests.append(("Geocoding", "GET",
        f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={K}"))
    tests.append(("Distance Matrix", "GET",
        f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.8918897&destinations=40.6905615,-73.9976592&key={K}"))
    tests.append(("Find Place", "GET",
        f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art&inputtype=textquery&fields=photos,formatted_address,name&key={K}"))
    tests.append(("Place Autocomplete", "GET",
        f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Paris&types=(cities)&key={K}"))
    tests.append(("Elevation", "GET",
        f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={K}"))
    tests.append(("Timezone", "GET",
        f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={K}"))
    tests.append(("Nearest Roads", "GET",
        f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796&key={K}"))
    tests.append(("Geolocation", "POST",
        f"https://www.googleapis.com/geolocation/v1/geolocate?key={K}"))
    tests.append(("Snap to Roads", "GET",
        f"https://roads.googleapis.com/v1/snapToRoads?path=60.170880,24.942795|60.170879,24.942796&key={K}"))
    tests.append(("Speed Limits", "GET",
        f"https://roads.googleapis.com/v1/speedLimits?path=60.170880,24.942795&key={K}"))
    tests.append(("Place Details", "GET",
        f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&key={K}"))
    tests.append(("Nearby Search", "GET",
        f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&key={K}"))
    tests.append(("Text Search", "GET",
        f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=123+main+street&key={K}"))
    tests.append(("Place Photos", "GET",
        f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_1PsG7ifgM&key={K}"))
    tests.append(("Query Autocomplete", "GET",
        f"https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=Paris&key={K}"))
    tests.append(("Place Embed", "GET",
        f"https://google.com/maps/embed/v1/place?q=Seattle&key={K}"))

    # ============ GEN AI & ML (10) ============
    tests.append(("Gemini Pro", "POST",
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={K}"))
    tests.append(("Gemini Pro Vision", "POST",
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro-vision:generateContent?key={K}"))
    tests.append(("Gemini Embedding", "POST",
        f"https://generativelanguage.googleapis.com/v1beta/models/embedding-001:embedContent?key={K}"))
    tests.append(("Gemini Count Tokens", "POST",
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:countTokens?key={K}"))
    tests.append(("Gemini Models List", "GET",
        f"https://generativelanguage.googleapis.com/v1beta/models?key={K}"))
    tests.append(("Gemini Files", "GET",
        f"https://generativelanguage.googleapis.com/v1beta/files?key={K}"))
    tests.append(("PaLM 2 (text-bison)", "POST",
        f"https://generativelanguage.googleapis.com/v1beta/models/text-bison-001:generateText?key={K}",
        200, "legacy PaLM 2 text generation"))
    tests.append(("Cloud Vision", "POST",
        f"https://vision.googleapis.com/v1/images:annotate?key={K}"))
    tests.append(("Text-to-Speech", "POST",
        f"https://texttospeech.googleapis.com/v1/text:synthesize?key={K}"))
    tests.append(("Speech-to-Text", "POST",
        f"https://speech.googleapis.com/v1/speech:recognize?key={K}"))

    # ============ NATURAL LANGUAGE (3) ============
    tests.append(("NL Sentiment", "POST",
        f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={K}"))
    tests.append(("NL Entities", "POST",
        f"https://language.googleapis.com/v1/documents:analyzeEntities?key={K}"))
    tests.append(("NL Syntax", "POST",
        f"https://language.googleapis.com/v1/documents:analyzeSyntax?key={K}"))

    # ============ TRANSLATION (1) ============
    tests.append(("Cloud Translation", "GET",
        f"https://translation.googleapis.com/language/translate/v2?target=en&q=Bonjour&key={K}"))

    # ============ YOUTUBE (2) ============
    tests.append(("YouTube Data", "GET",
        f"https://www.googleapis.com/youtube/v3/videos?part=snippet&chart=mostPopular&key={K}"))
    tests.append(("YouTube Search", "GET",
        f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={K}"))

    # ============ CLOUD STORAGE (1) — pass --project-id for real results ============
    tests.append(("Cloud Storage", "GET",
        f"https://www.googleapis.com/storage/v1/b?project={{project_id}}&maxResults=1&key={K}",
        "requires --project-id flag"))

    # ============ DRIVE (1) ============
    tests.append(("Google Drive", "GET",
        f"https://www.googleapis.com/drive/v3/files?pageSize=1&key={K}"))

    # ============ FIREBASE / IDENTITY (2) ============
    tests.append(("Firebase Auth (signUp)", "POST",
        f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={K}"))
    # FCM is handled in scan_key with proper POST body and Authorization header

    # ============ MAPS JS (1) ============
    tests.append(("Maps JavaScript", "GET",
        f"https://maps.googleapis.com/maps/api/js?key={K}&callback=initMap"))

    # ============ OAUTH2 (1) ============
    tests.append(("OAuth2 Token Info", "GET",
        f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={K}"))

    # ============ GOOGLE+ (1, deprecated) ============
    tests.append(("Google+ People", "GET",
        f"https://www.googleapis.com/plus/v1/people/me?key={K}"))

    return tests


def scan_key(apikey, json_output=False, generate_poc=False, project_id=None):
    """Run all tests against a single API key."""
    results = []
    tests = build_tests(apikey)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for name, method, url, *rest in tests:
            notes = rest[0] if rest else ""
            # Cloud Storage: use project_id if provided
            if name == "Cloud Storage" and project_id:
                url = url.replace("{project_id}", project_id)
                # Skip if no project_id
            if name == "Cloud Storage" and not project_id:
                continue
            fut = executor.submit(test_endpoint, name, method, url,
                                  apikey, notes=notes)
            futures[fut] = name

        # FCM: special handling with proper POST body + Authorization header
        fcm_url = f"https://fcm.googleapis.com/fcm/send"
        fcm_headers = {"Authorization": f"key={apikey}",
                       "Content-Type": "application/json"}
        fcm_body = {"registration_ids": ["ABC"]}
        fut = executor.submit(test_endpoint, "FCM (Server Key)", "POST",
                              fcm_url, apikey,
                              extra_headers=fcm_headers, json_data=fcm_body)
        futures[fut] = "FCM (Server Key)"

        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"service": futures[fut], "valid": False,
                                "auth_failed": False, "error": str(e)})

    # Sort: accessible first, then restricted, not_enabled, invalid, quota, other
    cat_order = {"success": 0, "restricted_key": 1, "api_not_enabled": 2,
                 "invalid_key": 3, "quota": 4, "error": 5, "other": 6}
    results.sort(key=lambda r: (cat_order.get(r.get("category", "other"), 9),
                                r.get("service", "")))

    accessible = [r for r in results if r.get("category") == "success"]
    restricted = [r for r in results if r.get("category") == "restricted_key"]
    not_enabled = [r for r in results if r.get("category") == "api_not_enabled"]
    denied = [r for r in results if r.get("category") == "invalid_key"]
    quota = [r for r in results if r.get("category") == "quota"]
    other = [r for r in results if r.get("category") in ("other", "error")]

    if json_output:
        report = {
            "key": apikey[:20] + "...",
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(results),
            "valid": len(accessible),
            "restricted": len(restricted),
            "not_enabled": len(not_enabled),
            "invalid_key": len(denied),
            "quota": len(quota),
            "other": len(other),
            "results": results
        }
        print(json.dumps(report, indent=2))
    else:
        print(f"\n{'='*70}")
        key_masked = apikey[:20] + "..." + apikey[-8:]
        print(f"  Google API Key: {key_masked}")
        print(f"  Tests: {len(results)}  |  ✅ {len(accessible)} accessible  |"
              f"  ⚠️  {len(restricted)} restricted  |  🔒 {len(not_enabled)} not enabled  |"
              f"  ❌ {len(denied)} invalid")
        if quota:
            print(f"  ⏳ {len(quota)} rate limited  |  ❓ {len(other)} other")
        else:
            print(f"  ❓ {len(other)} other")
        print(f"{'='*70}")

        if accessible:
            print(f"\n✅ ACCESSIBLE SERVICES ({len(accessible)}):")
            for r in accessible:
                note = f" - {r['note']}" if r.get("note") else ""
                print(f"  ✅ {r['service']:<30} (HTTP {r['status']}){note}")
                if generate_poc:
                    print(f"     curl -X GET '{r['url']}'")

        if restricted:
            print(f"\n⚠️  KEY RESTRICTED ({len(restricted)}):")
            for r in restricted:
                print(f"  ⚠️  {r['service']:<30} (HTTP {r['status']})")

        if not_enabled:
            print(f"\n🔒 API NOT ENABLED ({len(not_enabled)}):")
            for r in not_enabled:
                print(f"  🔒 {r['service']:<30} (HTTP {r['status']})")

        if denied:
            print(f"\n❌ INVALID KEY ({len(denied)}):")
            for r in denied:
                print(f"  ❌ {r['service']:<30} (HTTP {r['status']})")

        if quota:
            print(f"\n⏳ RATE LIMITED ({len(quota)}):")
            for r in quota:
                print(f"  ⏳ {r['service']:<30} (HTTP {r['status']})")

        if other:
            print(f"\n❓ OTHER ({len(other)}):")
            for r in other[:8]:
                resp = r.get("response", "")[:60]
                print(f"  ❓ {r['service']:<30} (HTTP {r['status']}: {resp})")
            if len(other) > 8:
                print(f"  ... and {len(other)-8} more")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"GapiChecker Enhanced v{__version__} — Google API Key Tester")
    parser.add_argument("--key", help="Single API key to test")
    parser.add_argument("--file", help="File containing API keys (one per line)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--poc", action="store_true",
                        help="Generate curl PoC commands for accessible endpoints")
    parser.add_argument("--project-id", help="GCP project ID for Cloud Storage test")
    parser.add_argument("--version", action="store_true", help="Show version")
    args = parser.parse_args()

    if args.version:
        print(f"GapiChecker Enhanced v{__version__}")
        print(f"Based on: {__original__}")
        sys.exit(0)

    keys = []
    if args.key:
        keys = [args.key.strip()]
    elif args.file:
        with open(args.file) as f:
            keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        parser.print_help()
        sys.exit(1)

    for i, key in enumerate(keys):
        if not key.startswith("AIza"):
            print(f"Skipping non-Google key: {key[:20]}...")
            continue
        scan_key(key, json_output=args.json, generate_poc=args.poc,
                 project_id=args.project_id)
        if i < len(keys) - 1:
            print()
