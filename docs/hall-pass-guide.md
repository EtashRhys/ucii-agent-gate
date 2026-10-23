# Hall Passes — Step-by-Step

**What a hall pass is:** permission for your agent to run **one specific dangerous command, once approved by the UCII Admin, inside a 2-hour window**. Destructive operations (deleting, destroying, wiping) are never part of a standing grant — a hall pass is the only way one runs, and it covers exactly one command, exactly as written, and nothing else.

**Cost:** $25 per pass. **Time:** the Admin reviews requests after verifying payment; expect your key within 24 hours of requesting. The 2-hour window does not start until you activate (step 3), so a slow email never eats your window.

You will handle three things in this process. Keep them separate in your mind — most confusion comes from mixing them up:

| Thing | What it is | Where you get it |
|---|---|---|
| **Control secret** | The secret from your credentials email. Proves you're the human owner. | Your credentials email (issued when your agent was set up) |
| **Request ID** | Identifies your hall-pass request. It is **not** a key and cannot activate anything by itself. | The panel shows it when you submit the request |
| **Activation key** | A one-time key that turns your approved request into a live pass. Shown to the Admin once; sent to you by email. Starts with `hp_`. | The UCII Admin's email, after approval |

---

## Step 1 — Request the pass (customer panel)

1. Open the customer panel and load your grant (Authority ID + control secret).
2. In the **Hall pass — $25** section, type the **exact command** your agent needs to run.

   ⚠️ **Character-for-character.** The pass is bound to the command exactly as written — every space, path, and flag. If the command your agent later tries differs by even one character, it will be denied. Double-check it before submitting; a wrong command means a new request.
3. Submit. The panel shows your **Request ID** and the status **pending**.

   Save the Request ID — you will need it in step 3. (That's all it's for. It is not your key.)

## Step 2 — Wait for approval (UCII Admin)

The Admin verifies your $25 payment, then approves the request and emails you your **activation key**.

- The key is generated at approval and shown to the Admin **once** — if the email doesn't arrive within 24 hours, contact the Admin. A lost key cannot be re-sent (only its fingerprint is stored); the unused request is inert — it can never be activated without the key — so simply submit a fresh request.
- Nothing is live yet. Your agent cannot run the command until you finish step 3.

## Step 3 — Activate the pass (customer panel)

1. In the same **Hall pass** section, find "Already have a key?"
2. Enter:
   - **Request ID** — from step 1
   - **Activation key** — from the Admin's email (starts with `hp_`; this is **not** the Request ID)
   - Your **control secret** is already loaded from the top of the panel.
3. Click **Activate hall pass**. The panel shows **active** and the exact time your window closes — **2 hours from now**.
4. Tell your agent to run the command **inside the window**.

## What the pass does and does not do

- ✅ Authorizes the **one exact command** you named, for your agent only, until the window closes.
- ❌ Does **not** authorize any other command — not a similar one, not the same command with a different file, not one extra character. Those are denied, exactly as if no pass existed.
- ❌ Is **not** a standing permission. When the window closes, it's gone; the next dangerous command needs a new pass.
- Your agent's normal grant is untouched throughout — the pass adds nothing to it and changes nothing when it expires.
- If the grant the pass belongs to is killed or replaced while a pass is active, the pass dies with it.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "invalid hall-pass key" on activate | The Request ID was pasted into the key field, or the key was copied with missing/extra characters | The key starts with `hp_`; the Request ID doesn't. Re-copy the key from the Admin's email exactly |
| "invalid hall-pass key" and you never got an email | The request hasn't been approved yet — no key exists | Wait for the approval email (up to 24 hours), or contact the Admin |
| Agent's command denied despite an active pass | The command doesn't match the approved text character-for-character, or the window has closed | Compare the command to your request exactly; if the window closed, request a new pass |
| Key lost / email deleted | Keys are shown once and stored only as a fingerprint | The unused request is inert without the key — submit a new request (and tell the Admin to expect it) |
| You lost your **control secret** | There is no self-service reset for it, by design | Contact the Admin (the operator). They can revoke and re-issue your grant with a fresh secret |
