# Aries Money Blueprint — Security Testing: Results & Remaining Work

Supersedes `security-test-plan.md`. That file was written before any testing; this one records what actually happened, corrects the several places the original plan was wrong, and lists what's still open.

**Environment facts learned during testing — these were not known when the original plan was written:**

- The live site is served by **Cloudflare Pages**, not Firebase Hosting. `firebase deploy --only hosting` does nothing to the public site. Frontend deploys are `cd C:\Users\aries\Desktop\AriesAI\index` then `npx wrangler pages deploy .`
- Backend deploys are `firebase deploy --only functions:api` from `C:\Users\aries\Desktop\AriesAI`
- Rules deploys are `firebase deploy --only firestore:rules`
- **After any functions deploy, wait 60 seconds.** Old Cloud Run instances keep serving the previous revision and will produce confusing results.
- The Turnstile iframe steals the DevTools console context. Check the frame selector reads `top` before every console command.
- The `RAW` harness dies on every page reload. Keep it as a Sources → Snippets entry and re-run with Ctrl+Enter.
- Your real IP for test purposes: `86.124.137.246`

---

## Scoreboard

| Test | Subject | Status |
|---|---|---|
| 1 | App Check enforced | ✅ Pass |
| 2 | CORS allowlist | ⚠️ Partial |
| 3 | 100KB body limit | ⬜ Not run |
| 4 | Bad-bot UA filter | ❌ Plan was wrong — control is unreachable |
| 5 | X-Forwarded-For spoofing | 🔴 **Failed → fixed** |
| 6 | Firestore key sanitization | ⚠️ Partial |
| 7 | Device ID hashing | ✅ Pass (salt moved to Secret Manager) |
| 8 | Rate limiting | ✅ Pass, clean 10/10 |
| 9 | Turnstile captcha | 🔴 **Failed → fixed** |
| 10 | Honeypot + timing | ⬜ Not run |
| 11 | Verified-email identity | ⚠️ Partial |
| 12 | Hard gate on disable2FA | ⚠️ Found a crash bug → fixed |
| 13 | askAI requires auth | ⬜ Not run |
| 14 | Prompt injection | ⚠️ Needs re-run on live frontend |
| 15 | Model params server-side | ⬜ Not run |
| 16 | Atomic AI quota | ⬜ Not run (limits corrected) |
| 17 | Groq envelope not leaked | ⚠️ Log side confirmed, browser side not |
| 18 | TOTP replay | ⬜ Inconclusive |
| 19 | MFA claims | 🔴 **Failed badly → fixed** |
| 20 | Ownership + revocation | 🔴 **Failed → fixed** |
| B1 | XSS in chat | ⚠️ Partial |
| B2 | Unauthenticated writes | 🔴 **Failed → fixed** |
| B3 | Cross-user reads | ❌ Plan premise was wrong |
| B4 | Error message leakage | ⚠️ 2 of 4 fixed |
| B5 | Password policy | ⬜ Not run |
| B6 | Security headers | ✅ Already present — original finding was wrong |

---

# Part 1 — What was found and fixed

## 🔴 Finding 1: IP spoofing (Test 5) — CRITICAL, fixed

**What was wrong.** `getClientIp` read `parts[parts.length - 2]`, assuming Google appends two entries to `X-Forwarded-For`. Logging proved it appends exactly **one**:

| Sent header | Arrived as | Old code picked |
|---|---|---|
| `1.2.3.4` | `1.2.3.4,86.124.137.246` | `1.2.3.4` ❌ |

**Impact.** Every IP-keyed control was bypassable with one header: the waitlist limit, the visit limit, and the `ip_*` quota backstop. Historical IP values in `waitlist`, `visitors`, and `security_logs` written before the fix are attacker-controllable and should not be trusted.

**Fix applied.** Read the last element instead:

```js
let ip = parts.length ? parts[parts.length - 1] : "";
if (!ip) ip = (req.socket && req.socket.remoteAddress) || "unknown";
```

**Verified.** Forged headers with one and three hops both resolved to the real IP.

---

## 🔴 Finding 2: MFA claim wipe + readable TOTP secret (Test 19) — CRITICAL, fixed

The most serious issue found. Three defects compounding.

**Defect A.** `handleVerify2FALogin` called raw `setCustomUserClaims(uid, {mfaVerified, mfaAt})`, which replaces the entire claims object and destroyed `twoFAEnabled`. The `updateMfaClaims` helper on the next line then merged into the already-stripped set, so the claim never returned. Enrollment set it correctly; **the first 2FA login destroyed it permanently.**

**Defect B.** `firestore.rules` used `request.auth.token.get('twoFAEnabled', false) != true`. With the claim missing, that evaluates true, the `||` short-circuits, and `mfaSatisfied()` collapses to just `signedIn()`.

**Defect C.** `/users/{uid}` was client-readable and holds **`twoFASecret`**.

**Impact, demonstrated live.** A password-only session (no 2FA code entered) read its own user document and got `twoFASecret` back — HTTP 200. Anyone with the password could extract the TOTP seed from their browser console and generate valid codes indefinitely. 2FA was ornamental against password compromise.

**Fixes applied.**
1. Deleted the raw `setCustomUserClaims` block in `handleVerify2FALogin`
2. Replaced the same pattern in `handleDisable2FA` with `updateMfaClaims(uid, {mfaVerified:false, mfaAt:0, twoFAEnabled:false})`
3. Changed the rules default to `get('twoFAEnabled', true)` — fails closed
4. Set `/users/{uid}` to `allow read: if false` — everything reaches it through the Admin SDK anyway

**⚠️ Still outstanding.** Fixing the wipe does not restore the claim on accounts that already lost it. Every account that completed a 2FA login before the fix still has stripped claims. See Part 2, item 1.

---

## 🔴 Finding 3: Turnstile secret invalid (Test 9) — fixed

`TURNSTILE_SECRET_KEY` held a wrong value. Cloudflare returned `invalid-input-secret` for every submission, meaning **the waitlist form rejected every real signup**. This looked like the captcha working correctly, which is why it went unnoticed.

The code discarded Cloudflare's `error-codes` field, so there was no way to tell a bad secret from a blocked bot. Added permanent logging:

```js
console.error("[turnstile]", JSON.stringify(captchaResult));
await logSecurityEvent(db, "captcha_failed", { ip, deviceId, codes: captchaResult["error-codes"] || [] });
```

**Keep that logging.** It contains nothing user-identifying and it is the only thing that makes this failure mode diagnosable.

Secret is now at version 3. **Still needs a successful end-to-end form submission to confirm** — see Part 2, item 3.

---

## 🔴 Finding 4: Unauthenticated conversation writes (Test B2) — fixed

`handleSaveConversation` had no auth check and no rate limit. Anyone with an App Check token could write 20KB per call, unbounded. Because line 710 uses `.set()` without merge, it also overwrote whole documents.

Added to both `handleSaveConversation` and `handleLoadConversation`:

```js
if (!data.authUid) {
  return res.status(401).json({ success: false, message: "Authentication required" });
}
```

Plus a 30/minute rate limit on the save path. **Verified:** both return 401 when signed out.

Side effect worth knowing: the anonymous branch of `conversationId` is now unreachable, which also closes the device-fingerprint collision risk the original plan flagged.

---

## 🔴 Finding 5: Revoked tokens still accepted (Test 20) — fixed

`clearMfa` calls `revokeRefreshTokens`, but `decodeIdToken` called `verifyIdToken(idToken)` without `checkRevoked`. A token captured before sign-out kept working for up to an hour — **demonstrated: a signed-out session successfully disabled 2FA.**

Fixed by adding the second argument:

```js
return await admin.auth().verifyIdToken(idToken, true); // checkRevoked
```

**Verified:** replay now returns 403.

---

## ⚠️ Finding 6: `.update()` on a missing document — fixed

`handleDisable2FA` called `.update()` on `users/<uid>`, which throws if the document doesn't exist. Calling disable on an account that never enrolled produced a 500 — and, because that handler returned `err.toString()`, the browser received the full Firestore path, project ID, and a real uid.

Fixed with `.set(..., { merge: true })` and a `fail()` call.

---

## ⚠️ Finding 7: Quota limits set to test values — fixed

- `AI_GLOBAL_DAILY_LIMIT` was **10**, the same as the per-user limit. The first user to send ten messages shut the assistant down site-wide for the rest of the day. Raised to **1000** (~$2.40/day worst case on a 70B model, likely under a third of that in practice).
- The `ip_*` bucket shared `AI_DAILY_LIMIT = 10`, so the second person on any shared IP got **zero** messages. Added `AI_IP_DAILY_LIMIT = 50` with a `limitFor(key)` helper, plus a distinct "this network" error message and a skip of the 3-second cooldown on the IP bucket (two people behind one NAT were throttling each other).

---

## ⚠️ Finding 8: Rate limiter failed open everywhere — scoped

`checkRateLimit` returned `{allowed: true}` on any Firestore error, meaning a database incident silently disabled **every** limit including TOTP brute-force protection.

Added a `failOpen = true` parameter, passed `false` at the three security-critical call sites (`2fa_login_user_`, `2fa_setup_verify_user_`, `2fa_disable_user_`), and left `visit` and `waitlist` permissive.

**Verified** with a temporary forced-throw: logs showed `failOpen: true` for `handleVisit` and `failOpen: false` for `handleVerify2FALogin`, exactly as intended.

Accepted trade-off: during a Firestore outage, 2FA users cannot log in at all.

---

## ⚠️ Finding 9: Chat history race condition — fixed

`loadSavedConversation()` was called at script parse time, before Firebase restored the session asynchronously. `auth.currentUser` was null, so an empty `idToken` went out, the backend built the **anonymous** conversation ID, and nothing loaded. History appeared to vanish on every refresh.

Fixed by moving the call into `onAuthStateChanged` with a `loadedConversationFor` guard against duplicate renders, plus a `clearChatWindow()` helper and an `assistant` → `ai` CSS class mapping.

Not a security bug, but it was breaking a real feature.

---

## ❌ Corrections to the original plan

Four tests were written on wrong assumptions. Recording them so they aren't re-run pointlessly.

**Test 4 (bad-bot filter).** The plan predicted 403s from curl. Actual: 401, because App Check at line 245 runs *before* the UA filter at line 257. Real crawlers never carry App Check tokens, so the `badBots` list is effectively dead code — the only request that can reach it is a real browser on your domain deliberately advertising itself as a crawler. Harmless, but not a control.

**Tests 6 and 7 (doc keys / device hashing).** The plan said to check `ai_usage` after calling `getRemainingAI`. That handler only reads; Firestore never creates documents on read. Use `saveAIConversation` to observe generated document IDs.

**Test B3 (cross-user reads).** The plan said to "load a conversation ID belonging to A." There is no conversation-ID parameter — `conversationId()` derives it server-side from the token. The ownership check at 729-731 is a backstop that production traffic cannot reach. The meaningful test is injecting `authUid` in the request body (see Part 2, item 6).

**Test B6 (security headers).** The original finding was simply wrong. Cloudflare Pages serves CSP, HSTS, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, and `Permissions-Policy` — all from the `_headers` file at the project root. **Already done.**

---

# Part 2 — Remaining work, in priority order

## 1. 🔴 Re-enroll 2FA on every affected account

**Why it's first:** Findings 2's fixes stop the claim wipe going forward, but do not repair accounts that already lost `twoFAEnabled`. Those accounts still carry stripped claims. The rules-level protection is now `allow read: if false` regardless, so the secret is no longer exposed — but the claim should still be correct.

**Steps per account:**
1. Log in, complete 2FA if prompted
2. Disable 2FA
3. Setup 2FA, scan the QR, enter a code — **screenshot the QR first**
4. Confirm:

```js
const res = await auth.currentUser.getIdTokenResult(true);
console.log("twoFAEnabled:", res.claims.twoFAEnabled, "| mfaVerified:", res.claims.mfaVerified);
```

Both must print `true`. `twoFAEnabled: undefined` means the wipe fix didn't deploy.

If you hit a 429, delete `rate_limits/2fa_disable_user_<uid>` in Firestore.

## 2. 🔴 Add 2FA recovery codes

You were locked out of your own account during testing and only recovered because you have console access to the database. **A real user in that position has no way back in.** There is no backup code, no email reset, no admin unlock.

Recommended shape: generate 8-10 single-use codes during `handleVerify2FASetup`, store them hashed alongside `twoFASecret`, display once, and accept one in place of a TOTP code in `handleVerify2FALogin`, marking it consumed.

Build this before you have real users — retrofitting it strands every existing 2FA account until they re-enroll.

## 3. 🔴 Confirm the waitlist actually works end to end

Finding 3 is fixed in configuration but never proven. Until a real submission succeeds, you cannot rule out that signups are still silently failing.

1. Load the site, wait 3+ seconds (the timing gate rejects under 2000ms)
2. Enter a fresh email, solve the captcha, submit
3. Expect the success modal
4. `firebase functions:log --only api --lines 10` — **no `[turnstile]` line** means it verified
5. Firestore → `waitlist` → confirm the document exists

If it still fails, read the `error-codes` in the log line rather than guessing.

## 4. 🟠 Finish the B4 error leaks

Two handlers still return `err.toString()` to the browser. Search anchors rather than line numbers, since the file has shifted:

```
findstr /n /c:"err.toString()" C:\Users\aries\Desktop\AriesAI\functions\index.js
```

Remaining: `handleSetup2FA` and `handleVerify2FASetup`. Each fix is the same shape as the ones already done:

```js
} catch (err) {
  return fail(res, 500, "Something went wrong. Please try again.", err, { action: "<name>" });
}
```

## 5. 🟠 Delete dead code

Now that `decodeIdToken` does `checkRevoked`, `requireAuth` is redundant and uncalled. Two auth paths in one file is how inconsistencies start.

```
findstr /n /c:"requireAuth" C:\Users\aries\Desktop\AriesAI\functions\index.js
```

One hit (the definition) means it's safe to remove.

Same for `mfaSatisfied()` and `signedIn()` in `firestore.rules` if nothing references them after the `allow read: if false` change — or keep them with a comment noting they're currently unused, so nobody assumes MFA is enforced at the database layer when it isn't.

## 6. 🟠 Test B3 properly (identity injection)

The one that actually matters. As **Account B**, with Account A's uid:

```js
const aUid = "PASTE_ACCOUNT_A_UID";
const load = await RAW({ action: "loadAIConversation", idToken: await TOK(), authUid: aUid, deviceId });
console.log("LOAD:", load.status, (load.body.messages || []).length);

await RAW({ action: "saveAIConversation", idToken: await TOK(), authUid: aUid, deviceId,
            messages: [{ role: "user", content: "written by B" }] });
```

**Pass:** B gets its own (or empty) conversation, and A's document is untouched. Line 271 should overwrite the injected `authUid` from the decoded token.

**Fail:** A's content comes back, or "written by B" lands in A's document. That would be a full cross-account read/write.

Same injection test applies to `askAI` — check which `ai_usage` bucket decrements.

## 7. 🟡 Tests never run

None are known-broken; they're just unverified.

- **Test 3** — 100KB body limit. Three console calls, two minutes.
- **Test 10** — honeypot and timing gate on the waitlist. Do it alongside item 3.
- **Test 13** — `askAI` returns 401 when signed out, and consumes no quota.
- **Test 15** — injected `max_tokens: 100000`, `n: 5`, and a different `model` are all ignored. Worth doing: `n: 5` would 5× your bill per request.
- **Test 16** — the parallel quota burst. Test 8 proved the rate-limit transaction serializes, and this is the same pattern in `consumeAiQuota`, so a failure is unlikely — but this is the one where a failure costs money directly.
- **Test 18** — TOTP replay. Previous attempt was inconclusive (the code had expired). Use the paired version: capture a fresh code, fire both calls in one paste.
- **Test B5** — password policy is client-side only. Consider enabling Firebase Auth's server-enforced policy under Authentication → Settings.

## 8. 🟡 Finish Test 14 on the live frontend

Prompt injection appeared to pass, but that was against a stale deployment. Now that the correct frontend is live, re-run the role-injection cases — particularly `role: "system"`, uppercase `"SYSTEM"`, and an assistant message in last position.

## 9. 🟡 Finish B1 (XSS) properly

The model declined to echo the payload, so the render path was never exercised. Bypass it:

```js
appendChatMessage("ai", "<img src=x onerror=\"alert('XSS')\"> <b>bold</b>");
```

Pass: literal visible text, no alert, "bold" not bold.

Then the static check, which is worth more than the live one because it catches paths you won't think to exercise:

```
findstr /n /c:"innerHTML" C:\Users\aries\Desktop\AriesAI\index\index.html
```

Any hit fed by `reply`, `msg`, `text`, `content`, or a Firestore value is a hole regardless of what the live test shows. Note your CSP includes `'unsafe-inline'` in `script-src`, so it would not stop an injected `onerror=` handler — `innerText` is what's actually protecting you.

## 10. 🟡 Confirm the CORS duplicate-header question (Test 2)

You set CORS twice: via the `onRequest({cors: [...]})` option and manually in the handler. Express's `res.set()` overwrites rather than appends, so there is probably only one header — and the site working at all is circumstantial proof, since browsers hard-fail on duplicates. Confirm at the byte level:

```
curl -s --http1.1 -D cors.txt -o nul -X POST "https://us-central1-aries-money-blueprint-30125.cloudfunctions.net/api" -H "Origin: https://ariesmoneyblueprint.site" -H "Content-Type: application/json" -A "Mozilla/5.0" -d "{\"action\":\"testDeployment\"}"
find /c /i "access-control-allow-origin" cors.txt
del cors.txt
```

Expect `1`.

---

# Part 3 — Before launch

Items that aren't tests but came out of testing.

**Set a Groq billing alert.** The global daily cap is a circuit breaker, not a budget control — it resets every midnight, so slow burn never trips it. Set the alert at whatever monthly figure would genuinely worry you.

**Log when the global cap trips.** Right now every user gets "The assistant is at capacity today" with no signal to you. Add a `logSecurityEvent` call so you find out from your logs rather than from a confused user.

**Consider a TTL on `visitors` and `rate_limits`.** Neither has any expiry or cleanup. `visitors` grows forever, and it now contains roughly 60 test documents (`xff-*`, `dbg-*`, `rl-*`, `rev-*`, `fo-*`). Firestore supports native TTL policies on a timestamp field, and you already write `createdAt`.

**Decide about per-day conversation IDs.** `conversationId` includes the date, so history becomes unreachable at midnight UTC. If you want continuity, the date has to come out of the key — which then makes `handleSaveConversation`'s 10-message trim the only thing bounding document size.

**Rotate anything that passed through a chat window.** During testing, an account password and several live ID tokens were pasted into conversation. Tokens expire within the hour, but the password should be changed if it hasn't been.

**Clean up the leftover `wrangler.jsonc` config.** It currently mixes a Workers-style `assets.directory` block with a Pages deployment. Should be a single object with `pages_build_output_dir` and no `assets` key.
