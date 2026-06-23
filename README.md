# GapiChecker Enhanced

Comprehensive Google API key security tester — tests API keys against 40+ Google service endpoints to map what access a leaked key provides.

**Forked from:** [z3n70/GapiChecker](https://github.com/z3n70/GapiChecker)  
**Additional endpoints inspired by:** [dodal-omkar/slayer-apis-scanner](https://github.com/dodal-omkar/slayer-apis-scanner), [DeathShotXD/GmapsXploit](https://github.com/DeathShotXD/GmapsXploit)

## Features

- Tests **43+ Google API endpoints** across Maps, Places, Roads, AI/ML, Cloud, YouTube, Firebase, and more
- **Concurrent scanning** with ThreadPoolExecutor (10 workers)
- **Smart classification** — detects API key rejection vs. API-not-enabled vs. permission-denied
- **JSON output** for automated processing
- **PoC mode** (`--poc`) generates curl commands for each accessible endpoint
- **File mode** (`--file`) for batch scanning multiple keys
- **No data exfiltration** — keys are only sent to Google's official API endpoints

## Interpreting Results

This tool tests each key **per-endpoint** — it tells you exactly which Google services accept the key.

**Important distinction:** A key that passes Google's auth infrastructure (what TruffleHog calls "Verified") is **not** the same as a key that works with Gemini, Cloud Vision, or any specific service. A Google API key restricted to Maps/Places will:
- ✅ Pass Google auth (valid format, active key)
- ✅ Work with Directions, Geocoding, Places, etc.
- ❌ Return 403/"not enabled" for Gemini AI, Cloud Vision, YouTube, etc.

Each test result shows the actual HTTP status and response — not a single pass/fail verdict.

## Services Tested

### Maps & Places (20)
Directions, Geocoding, Distance Matrix, Static Maps, Street View, Find Place, Place Autocomplete, Elevation, Timezone, Place Details, Nearby Search, Text Search, Place Photos, Query Autocomplete, Place Embed, Maps JavaScript, Geolocation, Nearest Roads, Snap to Roads, Speed Limits

### Generative AI & ML (10)
Gemini Pro, Gemini Pro Vision, Gemini Embedding, Gemini Count Tokens, Gemini Models List, Gemini Files, PaLM 2 (text-bison), Cloud Vision, Text-to-Speech, Speech-to-Text

### Natural Language (3)
Sentiment Analysis, Entity Extraction, Syntax Analysis

### Translation (1)
Cloud Translation

### YouTube (2)
YouTube Data, YouTube Search

### Cloud Storage (1)
Cloud Storage (GCS)

### Google Drive (1)
Google Drive API

### Firebase / Identity (2)
Firebase Auth (signUp), Firebase Cloud Messaging (FCM)

### Other (3)
OAuth2 Token Info, Google+ People (deprecated), Custom Search

## Usage

```bash
# Single key
python3 gapi-checker-enhanced.py --key AIzaSy...

# Batch from file
python3 gapi-checker-enhanced.py --file keys.txt

# JSON output
python3 gapi-checker-enhanced.py --key AIzaSy... --json

# Generate curl PoC commands
python3 gapi-checker-enhanced.py --file keys.txt --poc

# Cloud Storage test (requires a real GCP project ID)
python3 gapi-checker-enhanced.py --key AIzaSy... --project-id my-gcp-project

# Show version
python3 gapi-checker-enhanced.py --version
```

## Input Format

For batch mode (`--file`), add one key per line:

```
AIzaSyABC123...
AIzaSyDEF456...
```

Lines starting with `#` are ignored.

## Credits

- **[z3n70/GapiChecker](https://github.com/z3n70/GapiChecker)** — Original Maps API key checker that this project builds upon
- **[dodal-omkar/slayer-apis-scanner](https://github.com/dodal-omkar/slayer-apis-scanner)** — Additional endpoint classification and AI/ML service tests
- **[DeathShotXD/GmapsXploit](https://github.com/DeathShotXD/GmapsXploit)** — Maps API abuse methodology

## License

MIT
