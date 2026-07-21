# Investigation Walkthrough — SQL Injection to Cloud Storage Exfiltration

**Evidence:** Arkime v4.7.0 full packet capture
**Timezone:** UTC (set explicitly in Arkime → Settings → General → Timezone Format: UTC)
**Activity window:** 2025-09-24 01:09:55 – 01:17:38 UTC
**Victim host:** 10.0.14.53 (public-facing as 18.133.31.160), Express web app on TCP/3000
**Storage backend:** MinIO (S3-compatible) at `minio:9000`, bucket `zombiebucket`
**Attacker:** 91.90.124.21

---

## 0. Setting up the evidence

![Arkime General settings with Timezone Format set to UTC](Screenshots/utcsettings.png)
*Arkime → Settings → General. Timezone Format set to UTC before any session analysis.*

Before touching the sessions, the Arkime display timezone was switched to **UTC**. This matters more than it sounds: every timestamp quoted in an incident report has to be anchored to a single reference frame, otherwise the timeline you hand to legal or to another responder silently shifts by however many hours your browser happens to sit from GMT. All times below are UTC.

---

## 1. Identifying the attacker and the targeted service

![Arkime session list showing repeated connections from 91.90.124.21 to 10.0.14.53 on port 3000](Screenshots/q1.png)
*Session list filtered on the attacker address. Note the constant destination port 3000 and the randomised-parameter probes.*

Filtering the session list on the suspicious external address gives a dense block of TCP sessions, all following the same shape:

| Field | Value |
|---|---|
| Source IP | 91.90.124.21 |
| Source ports | ephemeral (19536, 24696, 24738, 24739, 24742, 24776, 24787, 24800, 24887, 24965, 24970, 24990 …) |
| Destination IP | 10.0.14.53 |
| Destination port | **3000** |
| URI | `18.133.31.160:3000/` and variants |

Two things stand out immediately.

First, **every** session terminates on port 3000 — not 80, not 443. The attacker is not spraying the host; they already know the application listens there and are talking to it exclusively. That is targeted behaviour, not opportunistic scanning.

Second, the rapid-fire cadence — a dozen-odd sessions inside roughly ninety seconds around 01:09–01:11 — plus probe URIs carrying junk parameters like `?oifsrehw1n=1` and `?nxz7isn76f=1` on port 13539. Randomly-generated parameter names are a classic fingerprint of automated scanning tooling checking how the application reflects unexpected input.

> **Q1 — Source IP `91.90.124.21`, targeted application port `3000`.**

---

## 2. Fingerprinting the home page response

![Raw GET / request from 91.90.124.21:24879 with a Chrome 140 User-Agent](Screenshots/q2part1.png)
*Source side of the baseline request — a spoofed Chrome 140 User-Agent.*

![Arkime HTTP metadata panel showing the Body MD5 field](Screenshots/q2part2.png)
*The parsed HTTP metadata, including the Body MD5 of the home page response.*

Drilling into one of the baseline `GET /` sessions, Arkime's HTTP metadata panel gives the parsed request/response pair:

- Method: `GET`
- Status code: `200`
- Hosts: `18.133.31.160:3000`, `18.133.31.160`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36`
- Content type: `text/html; charset=UTF-8`
- Server: Express (visible via the `x-powered-by` response header)
- **Body MD5: `ca1d882d9b1aac5f04f39509ee17f001`**

The MD5 is Arkime's hash of the response body as it crossed the wire. It's useful for two reasons: it lets you group every identical response together with a single filter instead of eyeballing packet bodies, and it gives you an integrity anchor — if the same URL later returns a different hash, the page changed between requests.

Worth noting the User-Agent here claims Chrome 140 on Windows. Hold that thought; it does not stay consistent.

> **Q2 — `ca1d882d9b1aac5f04f39509ee17f001`.**

---

## 3. Finding the injection point

![Sessions showing the /search injection URI alongside /download?id=6](Screenshots/q3and4.png)
*The injection appears at 01:16:49. Two sessions carry both the `/search` payload and the follow-on `/download?id=6`.*

Sorting the sessions forward in time past the reconnaissance burst, the traffic changes character at **01:16:49**. The URI column now shows:

```
18.133.31.160:3000/search?q=a'%20OR%20'1'%3D'1
```

URL-decoded, the `q` parameter is:

```
a' OR '1'='1
```

This is the textbook boolean-based SQL injection. The application is presumably building a query along the lines of:

```sql
SELECT * FROM objects WHERE name = '<user input>'
```

Substituting the payload yields:

```sql
SELECT * FROM objects WHERE name = 'a' OR '1'='1'
```

The single quote after `a` closes the intended string literal early, `OR '1'='1'` appends a condition that is unconditionally true, and the trailing quote from the original query balances the statement. The `WHERE` clause is now satisfied for every row, so instead of returning objects named `a`, the endpoint dumps the **entire table**.

That is the enumeration step. The attacker isn't trying to extract a specific record yet — they're asking the database to show them everything it has so they can pick a target.

> **Q3 — `/search`.**
> **Q4 — `a' OR '1'='1`.**

---

## 4. Reading the enumerated records

![Destination side of the session showing the JSON response with the presigned URL, key, filename and owner](Screenshots/q5and6and7and10.png)
*The JSON returned by the application — object key, filename, owner, and the full presigned MinIO URL. Four separate answers live in this one response.*

The response to the injected `/search` request — and the follow-on `/download` call — returns JSON from the Express app. Inspecting the destination side of session `10.0.14.53:3000` shows the record structure:

```json
{
  "id": 6,
  "key": "uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4",
  "filename": "cam06_ai_monitor_securityincident.mp4",
  "owner": "Frankenstein_Code"
}
```

Three separate answers fall out of this one blob.

**The owner field** is `Frankenstein_Code` — application-level metadata recording which account uploaded the objects. In an investigation this is the pivot point for the follow-up question "what else did that account touch, and was the account itself compromised or is it simply the legitimate uploader whose data got stolen?"

**The filename** identifies the camera: `cam06_ai_monitor_securityincident.mp4`. The naming convention is self-documenting — camera 06, AI monitor feed, flagged as a security incident. An attacker enumerating a table of CCTV clips and choosing the one literally labelled "security incident" is telling you something about intent.

**The key** is the S3 object key: `uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4`. It's worth being precise about what this is. S3 (and MinIO, which speaks the same API) has no real directories — storage is flat. The entire string including the `uploads/` prefix and the `/` character is **one single key**, unique within the bucket. The `uploads/` part only *looks* like a folder because tooling renders it that way; it carries no filesystem meaning. The 32-hex prefix `525e1f47…` is the application's de-duplication/uniqueness token prepended at upload time.

> **Q5 — `Frankenstein_Code`.**
> **Q6 — `cam06_ai_monitor_securityincident.mp4`.**
> **Q7 — `uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4`.**

---

## 5. The pivot: enumeration to retrieval

The session list shows the transition explicitly. Two sessions at 01:16:49 and 01:17:11 carry **both** URIs — the `/search` injection and `/download?id=6` — and then at **01:17:33** a clean standalone session:

![Single session at 01:17:33 requesting /download?id=6](Screenshots/q8.png)
*The isolated retrieval request, 01:17:33–01:17:38 UTC.*


```
18.133.31.160:3000/download?id=6
```

This is the canonical attacker workflow compressed into forty-four seconds: **discover** the injectable parameter, **enumerate** the records to learn valid object IDs, **retrieve** the one that looks valuable. The `id=6` is not guessed — it came directly out of the JSON the injection returned.

> **Q8 — path `/download`, ID `6`.**

---

## 6. The retrieval request — and the tooling slip

![Raw request showing the WindowsPowerShell User-Agent on GET /download?id=6](Screenshots/q9.png)
*The User-Agent has switched from Chrome to PowerShell — the exfiltration step was scripted.*

Opening the source side of session `91.90.124.21:24990`:

```http
GET /download?id=6 HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-CA) WindowsPowerShell/5.1.26100.6584
Host: 18.133.31.160:3000
```

The User-Agent has changed. Earlier requests presented as Chrome 140; this one is the **default UA emitted by PowerShell's `Invoke-WebRequest` / `Invoke-RestMethod` cmdlets**. The `Mozilla/5.0` prefix is vestigial camouflage that every HTTP client carries — the meaningful token is `WindowsPowerShell/5.1.26100.6584`.

Two inferences from a single header:

1. **The exfiltration was scripted, not browsed.** Nobody clicks a link and produces that UA. The attacker wrote a script to hit the endpoint and pull the response.
2. **The attacker didn't sanitise their tooling.** They spoofed a browser UA during reconnaissance but let the default through on the step that mattered. That inconsistency is itself an indicator — and a reminder that UA strings are trivially forgeable and should never be treated as identity, only as weak corroborating signal.

The `en-CA` locale is a further breadcrumb, though a soft one — locale is configurable and proves nothing on its own.

> **Q9 — `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-CA) WindowsPowerShell/5.1.26100.6584`.**

---

## 7. The presigned URL

The response to `/download?id=6` is a 555-byte JSON document from Express:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 555
Date: Wed, 24 Sep 2025 01:17:33 GMT
```

with a body containing:

```
http://minio:9000/zombiebucket/uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4
  ?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=minioadmin/20250924/us-east-1/s3/aws4_request
  &X-Amz-Date=20250924T011733Z
  &X-Amz-Expires=604800
  &X-Amz-Signature=1ef4d518be63a829d756c467b4c5e6cf7a0bc5f28497e9ffebb436827726b2936
  &X-Amz-SignedHeaders=host
```

### Why this is the real finding

The application does not serve the video itself. It mints a **presigned URL** — a time-limited, cryptographically signed link that grants bearer access to one specific object in the storage backend. Anyone holding that URL can fetch the object without any credentials of their own, until it expires.

Three things are wrong here, and they compound:

- **`X-Amz-Expires=604800`** — that is **seven days**. A download link that only needs to survive a single click has been given a week-long validity window. If that URL leaks into a proxy log, a browser history, a chat message, or a screenshot, it remains a working key to the object for seven days.
- **`X-Amz-Credential=minioadmin`** — the URL is signed with the **default MinIO administrator account**. The web app is authenticating to storage as root. Compromise the app's signing capability and you inherit administrative reach over the bucket, not scoped read access to one prefix.
- **No authorisation on `/download`.** The endpoint hands out a signed URL to whoever asks with a valid ID. Combined with the `/search` injection that leaks every valid ID, the two flaws chain into full enumeration and retrieval of the bucket's contents.

Individually, "verbose expiry" and "SQL injection in a search box" are findings you'd write up separately. Chained, they are a complete data-exfiltration path.

---

## 8. Reaching the storage service

The attacker followed the presigned URL. The final request lands on:

```
minio:9000
```

This is the internal service name and port of the MinIO container — the host component of the presigned URL, resolvable inside the application's network. The subsequent browser session confirms it, with the address bar showing `minio:9000/zombiebucket/uploads/525e1f476a399b2675777f6c2993aba1_cam06_ai_monitor_securityincident.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=mini…`

Note the architectural point: the application server (`10.0.14.53:3000`) and the storage service (`minio:9000`) are distinct endpoints. The data never transits the web app on the way out. Anyone monitoring only the application tier would see a `/download?id=6` and nothing more — the actual object transfer happens on a separate connection to a separate service. That is exactly the kind of gap that makes storage-tier access logging non-optional.

> **Q10 — `minio:9000`.**

---

## 9. Impact: what was in the file

![Video playing from minio:9000 with operator credentials overlaid on screen](Screenshots/q10_.png)
*The exfiltrated clip played back from the presigned URL. Address bar confirms `minio:9000`; the overlay at 0:07 exposes live operator credentials.*

The retrieved object is a ten-second clip of a monitored office — desk, CRT monitor, keyboard, scattered paperwork. At the seven-second mark, overlaid text appears within the on-screen tracking box:

```
Username: operator39 / Password: halloween2025
```

> **Q11 — `operator39` / `halloween2025`.**

This is the point where the incident stops being a vulnerability report and becomes a breach. The chain terminates in **working credentials for an operator account**, which means:

- The exposure is not bounded by the file. Whatever `operator39` can reach is now in scope.
- Those credentials must be treated as compromised and rotated immediately — along with any account sharing that password.
- Every other object in `zombiebucket` should be assumed enumerable, because the `/search` injection returned the full table. The attacker chose to pull one file; nothing stopped them pulling all of them.

---

## 10. Timeline

| Time (UTC) | Event |
|---|---|
| 01:09:55 | First session from 91.90.124.21 to 10.0.14.53:3000 |
| 01:09:55 – 01:11:49 | Reconnaissance burst; `GET /` repeatedly, plus randomised-parameter probes (`?oifsrehw1n=1`, `?nxz7isn76f=1`); Chrome 140 UA |
| 01:16:49 | SQL injection: `GET /search?q=a'%20OR%20'1'%3D'1` — full object table returned |
| 01:17:11 | Enumeration continues; `/download?id=6` first appears alongside `/search` |
| 01:17:33 | `GET /download?id=6` with PowerShell UA; presigned URL issued (`X-Amz-Date=20250924T011733Z`, 7-day expiry, signed as `minioadmin`) |
| 01:17:38 | Session closes; attacker follows presigned URL to `minio:9000` and retrieves the object |

Total elapsed from first contact to successful exfiltration: **under eight minutes.**

---

## 11. Findings and remediation

| # | Finding | Severity | Remediation |
|---|---|---|---|
| 1 | SQL injection in the `q` parameter of `/search` | **Critical** | Parameterised queries / prepared statements. Input validation is a secondary control, not the fix — the fix is never concatenating user input into SQL. |
| 2 | Presigned URLs signed with the `minioadmin` root credential | **Critical** | Create a dedicated service account with read-only access scoped to the `uploads/` prefix. The web app should never hold administrative storage credentials. |
| 3 | Presigned URL expiry set to 604800s (7 days) | **High** | Reduce to the shortest window the workflow tolerates — typically 60–300 seconds for a direct download. |
| 4 | `/download` performs no authorisation check on the requesting principal | **High** | Verify the caller is authenticated and entitled to the requested object ID before minting a URL. Object IDs are sequential and guessable even without the injection. |
| 5 | Sensitive credentials visible in stored video content | **High** | Rotate `operator39` immediately and audit its access history. Address the practice of leaving credentials displayed in monitored areas. |
| 6 | Sequential, enumerable object IDs (`id=6`) | **Medium** | Use non-sequential identifiers (UUIDs) so that authorisation failures aren't silently masked by ID obscurity — defence in depth, not a substitute for finding 4. |
| 7 | No apparent rate limiting on the application tier | **Medium** | The reconnaissance burst — a dozen sessions in ninety seconds from one source — drew no visible throttling. Rate limit and alert on it. |

### Detection gaps

- The randomised-parameter probes at 01:09–01:11 are a strong, cheap signal. No response was triggered.
- A single request producing a full-table response from `/search` should be anomalous by volume alone.
- A non-browser User-Agent (`WindowsPowerShell/…`) on a user-facing download endpoint is worth alerting on outright.
- Storage-tier access at `minio:9000` needs its own audit log. Application-tier logging alone would not have recorded the actual data transfer.

---

## 12. Method summary

The tradecraft here is unremarkable, which is the point — it needed no exotic technique:

1. **Reconnaissance** — automated probing of the application on port 3000 with a spoofed browser UA.
2. **Discovery** — boolean-based SQL injection found in the `/search` endpoint.
3. **Enumeration** — `a' OR '1'='1` returns the full object table: IDs, keys, filenames, owner.
4. **Target selection** — the record named `securityincident` picked from the dump.
5. **Access** — `/download?id=6` called via PowerShell script; the application obligingly minted a week-long, admin-signed presigned URL.
6. **Exfiltration** — object retrieved directly from `minio:9000`, bypassing the application tier entirely.
7. **Escalation potential** — credentials recovered from the video content, extending the compromise beyond the stolen file.

One injectable parameter plus one over-permissive storage integration produced a complete path from anonymous internet to working internal credentials in under eight minutes.

---

## Appendix — Evidence index

All screenshots referenced above are stored in `Screenshots/` alongside this document.

| File | Supports | Content |
|---|---|---|
| `utcsettings.png` | Setup | Arkime General settings, timezone set to UTC |
| `q1.png` | Q1 | Session list — 91.90.124.21 → 10.0.14.53:3000 |
| `q2part1.png` | Q2 | Raw `GET /` request, spoofed Chrome 140 UA |
| `q2part2.png` | Q2 | HTTP metadata panel with Body MD5 |
| `q3and4.png` | Q3, Q4, Q8 | `/search` injection URI and `/download?id=6` |
| `q5and6and7and10.png` | Q5, Q6, Q7, Q10 | JSON response — owner, filename, object key, presigned MinIO URL |
| `q8.png` | Q8 | Isolated `/download?id=6` session at 01:17:33 |
| `q9.png` | Q9 | Raw request with PowerShell User-Agent |
| `q10_.png` | Q10, Q11 | Video playback from `minio:9000` with credentials visible |
| `submission_form.png` | — | Completed submission form for reference |

**Folder layout assumed:**

```
Medium/
└── The Walking Packets/
    ├── walkthrough.md
    ├── answers.txt
    └── Screenshots/
        ├── utcsettings.png
        ├── q1.png
        ├── q2part1.png
        ├── q2part2.png
        ├── q3and4.png
        ├── q5and6and7and10.png
        ├── q8.png
        ├── q9.png
        ├── q10_.png
        └── submission_form.png
```

If you move the markdown file to a different level, adjust the `Screenshots/` prefix in the image links accordingly.
