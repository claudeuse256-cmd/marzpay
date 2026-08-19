
// server.js — HMK Stocks Wallet backend (deploy on Render)
// Host: https://marzpay.onrender.com
//
// REQUIRED ENVIRONMENT VARIABLES (set these in Render dashboard, never in code):
//   FIREBASE_SERVICE_ACCOUNT   -> full JSON of your Firebase service account key, as ONE LINE string
//                                 (must be a service account for the "whealthsphere" Firebase project)
//   MARZPAY_API_KEY            -> your MarzPay API Key (marz_...)
//   MARZPAY_API_SECRET         -> your MarzPay API Secret
//   MARZPAY_BASE_URL           -> https://wallet.wearemarz.com/api/v1
//   WEBHOOK_SECRET              -> (legacy, unused) previously a guessed header scheme; replaced by
//                                  MARZPAY_WEBHOOK_SIGNING_SECRET below, which matches MarzPay's real docs
//   MARZPAY_WEBHOOK_SIGNING_SECRET -> optional. Enables verifying that /webhook/marzpay calls genuinely
//                                  came from MarzPay. Get this value from MarzPay Dashboard >
//                                  Business Settings > Webhooks & Security > "Sign outgoing webhooks" >
//                                  Reveal > Copy. If unset, webhooks are accepted unsigned (MarzPay's
//                                  default), which still works but skips this integrity check.
//   PORT                        -> Render sets this automatically

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const fetch = require("node-fetch");
const FormData = require("form-data");
const crypto = require("crypto");
const { randomUUID } = crypto;

// ---------- Firebase Admin init ----------
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT env var. Server cannot start.");
  process.exit(1);
}
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error("FIREBASE_SERVICE_ACCOUNT is not valid JSON:", e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://whealthsphere-default-rtdb.firebaseio.com"
});
const db = admin.firestore();
const firebaseReady = true;

// ---------- MarzPay config ----------
const MARZPAY_BASE_URL = process.env.MARZPAY_BASE_URL || "https://wallet.wearemarz.com/api/v1";
const MARZPAY_API_KEY = process.env.MARZPAY_API_KEY;
const MARZPAY_API_SECRET = process.env.MARZPAY_API_SECRET;

if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
  console.warn("WARNING: MARZPAY_API_KEY / MARZPAY_API_SECRET not set. Deposit/withdraw calls will fail until configured in Render env vars.");
} else {
  // Log only lengths/prefixes, never the actual secret, to confirm the env vars loaded correctly.
  console.log(`MarzPay key loaded: prefix=${MARZPAY_API_KEY.slice(0, 6)}... length=${MARZPAY_API_KEY.length}`);
  console.log(`MarzPay secret loaded: length=${MARZPAY_API_SECRET.length}`);
  console.log(`MarzPay base URL: ${MARZPAY_BASE_URL}`);
  // Detect hidden whitespace/newlines that often sneak in from copy-pasting into Render's env var UI.
  const keyHasWhitespace = MARZPAY_API_KEY !== MARZPAY_API_KEY.trim();
  const secretHasWhitespace = MARZPAY_API_SECRET !== MARZPAY_API_SECRET.trim();
  if (keyHasWhitespace || secretHasWhitespace) {
    console.error(`WARNING: whitespace detected in MarzPay credentials! key=${keyHasWhitespace} secret=${secretHasWhitespace}. This will break Basic Auth. Re-paste the values in Render without leading/trailing spaces or newlines.`);
  }
}

function marzAuthHeader() {
  const key = (MARZPAY_API_KEY || "").trim();
  const secret = (MARZPAY_API_SECRET || "").trim();
  const raw = `${key}:${secret}`;
  return "Basic " + Buffer.from(raw).toString("base64");
}

// ---------- App setup ----------
const app = express();
app.use(cors());
// Capture the raw request body alongside the parsed JSON. MarzPay's webhook
// signature is computed over the exact raw body bytes — verifying against a
// re-serialized JSON.stringify(req.body) would fail whenever whitespace or
// key order differs from what MarzPay actually sent, even with the correct
// secret. This applies to all routes (cheap to do), but only /webhook/marzpay
// actually uses req.rawBody.
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString("utf8"); }
}));

// Temporary: log every incoming request so we can confirm requests are
// actually reaching the server (helpful while debugging deposit/withdraw issues).
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.path} at ${new Date().toISOString()}`);
  next();
});

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "modern-ai-wallet-server", firebaseReady });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, firebaseReady, time: new Date().toISOString() });
});

// ---------- DIAGNOSTIC: outbound IP checker ----------
// Visit this in a browser to see the exact IP address THIS Render instance
// is currently using for outbound requests (the one that needs to be
// whitelisted in MarzPay's dashboard). Render's outbound IP is a shared
// range, not a single fixed address, so this can change between deploys or
// over time — re-check here any time withdrawals start failing again with
// an IP-whitelist error, rather than assuming the old IP is still correct.
app.get("/api/my-outbound-ip", async (req, res) => {
  try {
    const ipRes = await fetch("https://api.ipify.org?format=json");
    const ipData = await ipRes.json();
    res.json({
      success: true,
      outboundIp: ipData.ip,
      note: "This is the IP this Render instance is currently using for outbound calls (e.g. to MarzPay). Whitelist this exact IP in MarzPay Dashboard > IP Whitelist. Re-check this endpoint if withdrawals start failing again, since Render's shared IP pool can change it."
    });
  } catch (err) {
    console.error("my-outbound-ip check failed:", err.message);
    res.status(502).json({ success: false, error: "Could not determine outbound IP right now. Try again in a moment." });
  }
});

// ---------- Auth middleware: verifies the Firebase ID token from the wallet page ----------
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ success: false, error: "Missing auth token." });
  }
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    req.userEmail = decoded.email;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: "Invalid or expired session. Please log in again." });
  }
}

// ---------- Helpers ----------
function normalizePhone(phone) {
  let p = String(phone || "").replace(/\s+/g, "");
  if (p.startsWith("0")) p = "+256" + p.slice(1);
  else if (p.startsWith("256")) p = "+" + p;
  else if (!p.startsWith("+256")) return "";
  return p;
}

function isValidAmount(amount) {
  return typeof amount === "number" && isFinite(amount) && amount >= 500;
}

// Withdrawal service fee. MarzPay's send-money call is made for the NET
// amount (after fee) — the user's wallet balance is still debited the FULL
// amount they asked to withdraw, and the fee difference simply isn't sent out.
const WITHDRAW_FEE_RATE = 0.08;
function computeWithdrawSplit(amount) {
  const fee = Math.round(amount * WITHDRAW_FEE_RATE * 100) / 100;
  const netAmount = Math.round((amount - fee) * 100) / 100;
  return { fee, netAmount };
}

// Emails allowed to call admin-only endpoints (status polling for any user's
// transaction, manual transaction overrides).
const ADMIN_EMAILS = ["srezra4@gmail.com"];

// ---------- Stale-transaction expiry ----------
// If MarzPay never calls our webhook (dropped callback, user never approved,
// etc.) a transaction can sit at status "pending" forever. That's dangerous:
// if MarzPay *later* delivers a delayed/retried webhook call for it, the
// webhook's only guard against double-crediting is `tx.status !== "pending"`.
// So a transaction the user already saw as "failed" client-side, but which
// server-side was still silently "pending", could get credited a second time
// whenever that late webhook finally arrives.
//
// Fix: after TX_TIMEOUT_MS with no resolution, we proactively flip the
// transaction to "failed" ourselves (refunding withdrawals). Once it's
// "failed", the webhook's existing guard (`tx.status !== "pending"`) makes
// any later, late-arriving webhook call a no-op — so it can never re-credit.
//
// TX_TIMEOUT_MS must be generous. If it's too short, a withdrawal that is
// still genuinely in flight with MarzPay gets marked "failed" and refunded
// here BEFORE MarzPay's real "completed" webhook arrives — the user then
// sees "failed"/"timeout" and gets their wallet balance back, even though
// the mobile money payout actually succeeded and landed on their phone.
// That's a real balance-drift bug (wallet refund + real money both
// received), not just a cosmetic timing issue, so err on the side of
// waiting longer rather than failing fast. 5 minutes comfortably covers
// normal MTN/Airtel confirmation times.
//
// This runs from two places, and both share this one function so there is
// never a double-refund race between them:
//   1. GET /api/transaction/:reference/status — checked every time the
//      client polls, so expiry is enforced even if this Render instance was
//      asleep the whole time and only just woke up to serve the poll.
//   2. A setInterval sweep below, as a backstop for whenever the instance
//      happens to be awake on its own.
const TX_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// IMPORTANT: this used to auto-refund withdrawals that were still "pending"
// after 5 minutes, on the assumption that no webhook after 5 minutes meant
// the payout never happened. In practice the payout can genuinely succeed
// on MarzPay's side while the webhook that would tell us so never arrives
// or arrives in a shape the handler didn't recognize — auto-refunding in
// that case gives the user their wallet balance back AND the real mobile
// money payout, a real balance-drift bug, not just a cosmetic one.
//
// So withdrawals no longer auto-fail/auto-refund here. Instead, after
// TX_TIMEOUT_MS a still-pending withdrawal is flipped to "unconfirmed" —
// a distinct status meaning "we don't know the outcome, don't trust either
// balance state until a human checks MarzPay's dashboard for this
// reference and resolves it via POST /api/admin/update-transaction."
// Deposits are unaffected by this change: nothing was ever credited for a
// still-pending deposit, so marking it "failed" here has no balance risk.
async function expireIfStale(txRef) {
  return db.runTransaction(async (t) => {
    const snap = await t.get(txRef);
    if (!snap.exists) return null;
    const tx = snap.data();

    if (tx.status !== "pending") return tx; // already resolved, nothing to do

    const createdMs = tx.createdAt && tx.createdAt.toMillis ? tx.createdAt.toMillis() : 0;
    const ageMs = Date.now() - createdMs;
    if (!createdMs || ageMs < TX_TIMEOUT_MS) return tx; // not stale yet

    if (tx.type === "withdraw") {
      // Do NOT touch balance here — we genuinely don't know whether the
      // payout succeeded. Flag for manual/admin resolution instead.
      const updated = {
        status: "unconfirmed",
        failReason: "No webhook confirmation received within 5 minutes. This does NOT mean the transfer failed — MarzPay payouts can succeed without a webhook arriving. Support will verify with MarzPay directly and resolve this manually.",
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      t.update(txRef, updated);
      console.warn(`Withdrawal ${tx.reference} timed out waiting for webhook — marked unconfirmed, NOT auto-refunded. Needs manual review.`);
      return { ...tx, ...updated, status: "unconfirmed" };
    }

    // Deposits: nothing was ever credited while pending, so it's safe to
    // resolve this as failed outright — no balance to reverse.
    const updated = {
      status: "failed",
      failReason: "Timed out waiting for network confirmation (5 min). If money was already sent, contact support before retrying.",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };
    t.update(txRef, updated);
    return { ...tx, ...updated, status: "failed" };
  });
}

// ---------- ACCOUNT NAME VERIFICATION ----------
// Before a withdrawal is submitted, the client calls this to ask MarzPay who
// a phone number is actually registered to (KYC-style phone verification).
// The user then confirms on-screen that the returned name is really theirs
// before the withdrawal proceeds. This never touches balance or Firestore —
// it's a pure lookup — so it's safe to call as many times as needed.
app.post("/api/verify-account-name", requireAuth, async (req, res) => {
  try {
    const { phone } = req.body;
    const cleanPhone = normalizePhone(phone);
    if (!cleanPhone) {
      return res.status(400).json({ success: false, error: "Enter a valid Uganda phone number." });
    }

    // MarzPay's phone-verification endpoint wants the number WITHOUT the
    // leading "+" (format: 256XXXXXXXXX), unlike collect-money/send-money
    // which want the "+256..." form.
    const lookupPhone = cleanPhone.replace(/^\+/, "");

    let marzRes;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/phone-verification/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": marzAuthHeader()
        },
        body: JSON.stringify({ phone_number: lookupPhone })
      });
    } catch (fetchErr) {
      console.error("Network error calling MarzPay phone-verification:", fetchErr.message);
      return res.status(502).json({ success: false, error: "Could not reach the verification service. Try again." });
    }

    const marzData = await marzRes.json().catch(() => ({}));

    if (!marzRes.ok || !marzData.success) {
      const msg = marzData.message || "This number is not registered on mobile money, or could not be verified.";
      return res.status(marzRes.status === 404 ? 404 : 400).json({ success: false, error: msg });
    }

    const info = marzData.data || {};
    if (!info.full_name) {
      return res.status(404).json({ success: false, error: "Could not retrieve a registered name for this number." });
    }

    res.json({
      success: true,
      phone: cleanPhone,
      fullName: info.full_name,
      firstName: info.first_name || null,
      lastName: info.last_name || null
    });
  } catch (err) {
    console.error("verify-account-name error:", err);
    res.status(500).json({ success: false, error: "Server error while verifying account name." });
  }
});

// ---------- DEPOSIT ----------
// User calls this from wallet.html. We create a pending transaction in Firestore,
// then call MarzPay collect-money. Balance is only credited once MarzPay confirms
// via webhook (see /webhook/marzpay below) — never credited optimistically here.
app.post("/api/deposit", requireAuth, async (req, res) => {
  try {
    const { phone, amount } = req.body;
    const cleanPhone = normalizePhone(phone);
    const amt = Number(amount);

    if (!cleanPhone || !isValidAmount(amt)) {
      return res.status(400).json({ success: false, error: "Valid phone and amount (min 500 UGX) are required." });
    }

    const txRef = db.collection("transactions").doc();
    const reference = randomUUID(); // MarzPay requires a valid UUID v4 reference

    await txRef.set({
      uid: req.uid,
      type: "deposit",
      amount: amt,
      phone: cleanPhone,
      status: "pending",
      reference,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    let marzRes;
    try {
      const form = new FormData();
      form.append("phone_number", cleanPhone);
      form.append("amount", String(amt));
      form.append("country", "UG");
      form.append("reference", reference);
      form.append("description", "HMK Stocks Wallet deposit");
      form.append("callback_url", "https://marzpay.onrender.com/webhook/marzpay");

      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: "POST",
        headers: {
          ...form.getHeaders(),
          "Authorization": marzAuthHeader()
        },
        body: form
      });
      console.log(`MarzPay collect-money response status: ${marzRes.status}, reference=${reference}`);
    } catch (fetchErr) {
      console.error("Network error calling MarzPay collect-money:", fetchErr.message);
      await txRef.update({
        status: "failed",
        failReason: "Network error reaching MarzPay: " + fetchErr.message,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(502).json({ success: false, error: "Could not reach MarzPay. Check MARZPAY_BASE_URL env var and Render logs." });
    }

    const marzData = await marzRes.json().catch(() => ({}));

    if (!marzRes.ok) {
      console.error("MarzPay collect-money failed:", marzRes.status, JSON.stringify(marzData));
      await txRef.update({
        status: "failed",
        failReason: marzData.message || `MarzPay error (HTTP ${marzRes.status})`,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(400).json({
        success: false,
        error: marzData.message || `MarzPay rejected the request (HTTP ${marzRes.status}). Check Render logs for details.`
      });
    }

    await txRef.update({
      marzpayResponse: marzData,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, reference, message: "Deposit initiated. Approve the mobile money prompt on your phone." });
  } catch (err) {
    console.error("Deposit error:", err);
    res.status(500).json({ success: false, error: "Server error while processing deposit." });
  }
});

// ---------- WITHDRAW ----------
// Balance is deducted immediately (reserved) so a user can't withdraw the same
// funds twice while a payout is in flight. If MarzPay ultimately fails the
// payout, the webhook refunds the reserved amount back to the user.
app.post("/api/withdraw", requireAuth, async (req, res) => {
  try {
    const { phone, amount, verifiedName } = req.body;
    const cleanPhone = normalizePhone(phone);
    const amt = Number(amount);

    if (!cleanPhone || !isValidAmount(amt)) {
      return res.status(400).json({ success: false, error: "Valid phone and amount (min 500 UGX) are required." });
    }

    // Require that the client actually ran /api/verify-account-name for this
    // exact phone number first and the user confirmed the returned name.
    // This re-verifies server-side rather than trusting the client's word —
    // we look the number up again and compare, so a tampered client request
    // can't skip the check.
    let verification;
    try {
      const lookupPhone = cleanPhone.replace(/^\+/, "");
      const verifyRes = await fetch(`${MARZPAY_BASE_URL}/phone-verification/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": marzAuthHeader()
        },
        body: JSON.stringify({ phone_number: lookupPhone })
      });
      verification = await verifyRes.json().catch(() => ({}));
      if (!verifyRes.ok || !verification.success || !verification.data || !verification.data.full_name) {
        return res.status(400).json({
          success: false,
          error: verification.message || "Could not verify this account name. Please re-verify and try again."
        });
      }
    } catch (verifyErr) {
      console.error("Withdraw name re-verification network error:", verifyErr.message);
      return res.status(502).json({ success: false, error: "Could not reach the verification service. Try again." });
    }

    const registeredName = verification.data.full_name;
    const claimedName = String(verifiedName || "").trim();
    if (!claimedName || claimedName.toLowerCase() !== registeredName.toLowerCase()) {
      return res.status(400).json({
        success: false,
        error: `Name mismatch. This number is registered to "${registeredName}". Please re-verify before withdrawing.`
      });
    }

    const { fee, netAmount } = computeWithdrawSplit(amt);

    const userRef = db.collection("users").doc(req.uid);
    const txRef = db.collection("transactions").doc();
    const reference = randomUUID(); // MarzPay requires a valid UUID v4 reference

    // Transaction-safe balance check + reservation.
    // NOTE: the FULL amount (amt) is deducted from the user's balance — the
    // 8% fee is not sent out, only netAmount is, but the user still pays the
    // full amount out of their wallet.
    await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw new Error("User account not found.");
      const balance = Number(userDoc.data().balance || 0);
      if (balance < amt) throw new Error("Insufficient balance.");

      t.update(userRef, {
        balance: admin.firestore.FieldValue.increment(-amt)
      });
      t.set(txRef, {
        uid: req.uid,
        type: "withdraw",
        amount: amt,
        fee,
        netAmount,
        phone: cleanPhone,
        accountName: registeredName,
        status: "pending",
        reference,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    const withdrawForm = new FormData();
    withdrawForm.append("phone_number", cleanPhone);
    withdrawForm.append("amount", String(netAmount)); // send only the NET amount after fee
    withdrawForm.append("country", "UG");
    withdrawForm.append("reference", reference);
    withdrawForm.append("description", "HMK Stocks Wallet withdrawal");
    withdrawForm.append("callback_url", "https://marzpay.onrender.com/webhook/marzpay");

    const marzRes = await fetch(`${MARZPAY_BASE_URL}/send-money`, {
      method: "POST",
      headers: {
        ...withdrawForm.getHeaders(),
        "Authorization": marzAuthHeader()
      },
      body: withdrawForm
    });

    const marzData = await marzRes.json().catch(() => ({}));

    if (!marzRes.ok) {
      console.error("MarzPay send-money failed:", marzRes.status, JSON.stringify(marzData));
      // Refund the reserved balance since the payout call itself failed
      await db.runTransaction(async (t) => {
        t.update(userRef, { balance: admin.firestore.FieldValue.increment(amt) });
        t.update(txRef, {
          status: "failed",
          failReason: marzData.message || `MarzPay error (HTTP ${marzRes.status})`,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      });
      return res.status(400).json({
        success: false,
        error: marzData.message || `MarzPay rejected the request (HTTP ${marzRes.status}).`
      });
    }

    await txRef.update({
      marzpayResponse: marzData,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      reference,
      amount: amt,
      fee,
      netAmount,
      message: `Withdrawal submitted for processing. You will receive UGX ${netAmount.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})} after the 8% service fee.`
    });
  } catch (err) {
    console.error("Withdraw error:", err);
    res.status(400).json({ success: false, error: err.message || "Server error while processing withdrawal." });
  }
});

// ---------- TRANSACTION STATUS (polled by wallet.html) ----------
// The client polls this every few seconds after submitting a deposit/withdraw
// in automatic mode. This is also where stale "pending" transactions actually
// get resolved — see expireIfStale() above. Deposits resolve to "failed";
// withdrawals resolve to "unconfirmed" (never auto-refunded, since the
// payout can genuinely have succeeded even without a webhook arriving).
app.get("/api/transaction/:reference/status", requireAuth, async (req, res) => {
  try {
    const { reference } = req.params;
    if (!reference) {
      return res.status(400).json({ success: false, error: "Missing reference." });
    }

    const txSnap = await db.collection("transactions").where("reference", "==", reference).limit(1).get();
    if (txSnap.empty) {
      return res.status(404).json({ success: false, error: "Transaction not found." });
    }

    const txDoc = txSnap.docs[0];
    let tx = txDoc.data();

    // Only the owner of the transaction (or an admin) may poll its status.
    if (tx.uid !== req.uid && !ADMIN_EMAILS.includes((req.userEmail || "").toLowerCase())) {
      return res.status(403).json({ success: false, error: "Not authorized." });
    }

    if (tx.status === "pending") {
      const resolved = await expireIfStale(txDoc.ref);
      if (resolved) tx = resolved;
    }

    res.json({
      success: true,
      status: tx.status,
      type: tx.type,
      amount: tx.amount,
      fee: typeof tx.fee === "number" ? tx.fee : null,
      netAmount: typeof tx.netAmount === "number" ? tx.netAmount : null,
      failReason: tx.failReason || null
    });
  } catch (err) {
    console.error("Transaction status error:", err);
    res.status(500).json({ success: false, error: "Server error while checking transaction status." });
  }
});

// ---------- MARZPAY WEBHOOK ----------
// MarzPay calls this URL when a deposit or withdrawal finishes processing.
// This is the ONLY place a user's balance is credited for a deposit.
//
// Signature verification (per MarzPay's docs: wallet.wearemarz.com/documentation/webhooks):
//   - Only active if MARZPAY_WEBHOOK_SIGNING_SECRET is set. MarzPay's webhook
//     signing is OPT-IN — you turn it on in Business Settings > Webhooks &
//     Security, click Reveal, and copy that secret into this env var. Without
//     it, MarzPay sends plain unsigned JSON and this check is skipped (not
//     recommended for production, but matches their default behavior).
//   - Headers: X-MarzPay-Timestamp (unix seconds) and X-MarzPay-Signature,
//     formatted as "t={timestamp},v1={hex_signature}".
//   - Signature = HMAC-SHA256("{timestamp}.{raw_body}", signing_secret),
//     compared against the v1 hex value using a constant-time check.
//   - MUST use the raw request body bytes (req.rawBody, captured by the
//     express.json() verify hook above) — hashing JSON.stringify(req.body)
//     instead would silently fail on any whitespace/key-order difference,
//     even with the right secret.
function verifyMarzPaySignature(req) {
  const signingSecret = process.env.MARZPAY_WEBHOOK_SIGNING_SECRET;
  if (!signingSecret) return { ok: true, checked: false }; // signing not enabled — nothing to verify

  const timestamp = req.headers["x-marzpay-timestamp"];
  const signatureHeader = req.headers["x-marzpay-signature"];
  const rawBody = req.rawBody || "";

  if (!timestamp || !signatureHeader) {
    return { ok: false, checked: true, reason: "Missing signature headers." };
  }

  const match = /v1=([a-f0-9]+)/.exec(signatureHeader);
  const received = match ? match[1] : "";
  if (!received) {
    return { ok: false, checked: true, reason: "Malformed X-MarzPay-Signature header." };
  }

  const expected = crypto
    .createHmac("sha256", signingSecret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  const expectedBuf = Buffer.from(expected, "utf8");
  const receivedBuf = Buffer.from(received, "utf8");
  const valid = expectedBuf.length === receivedBuf.length && crypto.timingSafeEqual(expectedBuf, receivedBuf);

  return valid ? { ok: true, checked: true } : { ok: false, checked: true, reason: "Signature mismatch." };
}

// ---------- Webhook diagnostic logging ----------
// Every call to /webhook/marzpay is recorded here VERBATIM — regardless of
// whether it was recognized, matched a transaction, or passed signature
// verification — so you can see exactly what MarzPay actually sent after a
// real withdrawal, instead of guessing at their payload shape. This is the
// single most useful tool for diagnosing "money arrived but stayed Pending":
// check GET /api/admin/webhook-logs (below) right after your next withdrawal.
async function logWebhookCall(entry) {
  try {
    await db.collection("webhookLogs").add({
      ...entry,
      receivedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  } catch (e) {
    console.error("Failed to log webhook call:", e.message);
  }
}

// Pull a value out of the payload trying every key shape MarzPay (or any
// similarly-structured provider) plausibly uses, since payload shape can
// differ from what we originally coded against. Checked in order; first
// match wins.
function pluckFirst(obj, paths) {
  for (const path of paths) {
    const val = path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
    if (val !== undefined && val !== null && val !== "") return val;
  }
  return undefined;
}

app.post("/webhook/marzpay", async (req, res) => {
  const verification = verifyMarzPaySignature(req);

  // Log the raw call FIRST, before any other processing can throw and skip
  // it — an unrecognized or rejected payload is exactly the case we most
  // need a record of.
  await logWebhookCall({
    signatureOk: verification.ok,
    signatureChecked: verification.checked,
    signatureReason: verification.reason || null,
    headers: {
      "x-marzpay-timestamp": req.headers["x-marzpay-timestamp"] || null,
      "x-marzpay-signature": req.headers["x-marzpay-signature"] || null,
      "content-type": req.headers["content-type"] || null
    },
    rawBody: req.rawBody || null,
    body: req.body || null
  });

  try {
    if (!verification.ok) {
      console.warn("Rejected MarzPay webhook: " + verification.reason);
      return res.status(401).json({ success: false, error: "Invalid webhook signature." });
    }

    // Shape-tolerant extraction. MarzPay's documented shape nests everything
    // under `transaction` (e.g. transaction.reference, transaction.status),
    // but we also check top-level and `data`-wrapped variants as a fallback
    // in case the real payload differs from what we coded against — this is
    // exactly the kind of mismatch that leaves a transaction stuck pending
    // even though the payout genuinely succeeded.
    const eventType = pluckFirst(req.body, ["event_type", "event", "type"]);
    const reference = pluckFirst(req.body, [
      "transaction.reference", "reference", "data.reference", "data.transaction.reference"
    ]);
    const status = pluckFirst(req.body, [
      "transaction.status", "status", "data.status", "data.transaction.status"
    ]);

    if (!reference) {
      console.warn("Webhook missing reference in any known shape. Full body:", JSON.stringify(req.body));
      return res.status(400).json({ success: false, error: "Missing reference." });
    }

    const txSnap = await db.collection("transactions").where("reference", "==", reference).limit(1).get();
    if (txSnap.empty) {
      console.warn("Webhook received for unknown reference:", reference);
      return res.status(404).json({ success: false, error: "Transaction not found." });
    }

    const txDoc = txSnap.docs[0];
    const tx = txDoc.data();

    if (tx.status !== "pending") {
      // Already processed — acknowledge without double-crediting
      return res.json({ success: true, message: "Already processed." });
    }

    // Prefer event_type (collection.completed / collection.failed / disbursement.completed / disbursement.failed)
    // since MarzPay documents this as the authoritative "final status" signal; fall back to status field.
    // Widened to cover more synonyms a webhook payload could plausibly use —
    // this is intentionally broad since the cost of missing a real success
    // (leaving it "pending" forever) is worse than the cost of a slightly
    // over-inclusive match.
    const normalizedEvent = String(eventType || "").toLowerCase();
    const normalizedStatus = String(status || "").toLowerCase().trim();
    const successStatuses = ["completed", "complete", "successful", "success", "paid", "confirmed"];
    const failStatuses = ["failed", "failure", "cancelled", "canceled", "rejected", "declined", "expired"];
    const isSuccess = normalizedEvent.endsWith(".completed") || successStatuses.includes(normalizedStatus);
    const isFailed = normalizedEvent.endsWith(".failed") || normalizedEvent.endsWith(".cancelled")
      || failStatuses.includes(normalizedStatus);

    const userRef = db.collection("users").doc(tx.uid);

    if (isSuccess) {
      await db.runTransaction(async (t) => {
        if (tx.type === "deposit") {
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(tx.amount) });
        }
        // For withdrawals, balance was already deducted at request time — nothing more to do.
        t.update(txDoc.ref, {
          status: "completed",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          webhookPayload: req.body
        });
      });
      console.log(`Webhook: marked ${reference} completed (event=${normalizedEvent || "n/a"}, status=${normalizedStatus || "n/a"})`);
    } else if (isFailed) {
      await db.runTransaction(async (t) => {
        if (tx.type === "withdraw") {
          // Refund reserved balance back to user since payout failed
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(tx.amount) });
        }
        t.update(txDoc.ref, {
          status: "failed",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          webhookPayload: req.body
        });
      });
      console.log(`Webhook: marked ${reference} failed (event=${normalizedEvent || "n/a"}, status=${normalizedStatus || "n/a"})`);
    } else {
      // Unrecognized status — log and leave pending for manual review.
      // Check webhookLogs / this transaction's `note` field to see the
      // exact event_type/status MarzPay actually sent, then add it to
      // successStatuses/failStatuses above once confirmed.
      console.warn(`Webhook: unrecognized status for ${reference}: event=${normalizedEvent || "n/a"} status=${normalizedStatus || "n/a"}`);
      await txDoc.ref.update({
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        webhookPayload: req.body,
        note: `Unrecognized webhook status: event_type=${eventType || "n/a"} status=${status || "n/a"}`
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).json({ success: false, error: "Webhook processing error." });
  }
});

// ---------- Admin: view recent webhook deliveries (diagnostic) ----------
// Visit this after a real withdrawal to see exactly what MarzPay sent,
// whether the signature check passed, and whether it matched a transaction.
// Requires an admin-email Firebase session (same check as update-transaction).
app.get("/api/admin/webhook-logs", requireAuth, async (req, res) => {
  try {
    if (!ADMIN_EMAILS.includes((req.userEmail || "").toLowerCase())) {
      return res.status(403).json({ success: false, error: "Not authorized." });
    }
    const limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
    const snap = await db.collection("webhookLogs").orderBy("receivedAt", "desc").limit(limit).get();
    const logs = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    res.json({ success: true, logs });
  } catch (err) {
    console.error("webhook-logs error:", err);
    res.status(500).json({ success: false, error: "Server error while fetching webhook logs." });
  }
});

// ---------- Admin: manual transaction status override (optional utility) ----------
// Protects itself by requiring the caller's Firebase token to match an admin email.
app.post("/api/admin/update-transaction", requireAuth, async (req, res) => {
  try {
    if (!ADMIN_EMAILS.includes((req.userEmail || "").toLowerCase())) {
      return res.status(403).json({ success: false, error: "Not authorized." });
    }
    const { transactionId, newStatus } = req.body;
    if (!transactionId || !["completed", "failed", "pending", "unconfirmed"].includes(newStatus)) {
      return res.status(400).json({ success: false, error: "Invalid input." });
    }

    const txRef = db.collection("transactions").doc(transactionId);
    const txSnap = await txRef.get();
    if (!txSnap.exists) return res.status(404).json({ success: false, error: "Transaction not found." });
    const tx = txSnap.data();

    if (tx.status === newStatus) {
      return res.json({ success: true, message: "No change." });
    }

    const userRef = db.collection("users").doc(tx.uid);

    await db.runTransaction(async (t) => {
      // Reverse effects of old status, then apply effects of new status, so
      // balances stay consistent no matter what transition the admin makes.
      if (tx.type === "deposit") {
        if (tx.status === "completed" && newStatus !== "completed") {
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(-tx.amount) });
        }
        if (tx.status !== "completed" && newStatus === "completed") {
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(tx.amount) });
        }
      }
      if (tx.type === "withdraw") {
        // withdraw amount is deducted at request time; "failed" means refunded
        if (tx.status !== "failed" && newStatus === "failed") {
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(tx.amount) });
        }
        if (tx.status === "failed" && newStatus !== "failed") {
          t.update(userRef, { balance: admin.firestore.FieldValue.increment(-tx.amount) });
        }
      }
      t.update(txRef, { status: newStatus, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Admin update-transaction error:", err);
    res.status(500).json({ success: false, error: "Server error." });
  }
});

// ---------- Background sweep for stale pending transactions ----------
// Backstop only. On Render's free tier this instance sleeps when idle, so
// this interval will NOT catch everything on its own — the real safety net
// is expireIfStale() being called from GET /api/transaction/:reference/status
// every time the client polls (see above). This sweep just cleans things up
// promptly whenever the server happens to be awake, so pending transactions
// don't visibly linger in a user's history longer than necessary.
// NOTE: the query below (status == "pending" AND createdAt <= cutoff) needs a
// Firestore composite index on the "transactions" collection. The first time
// this runs, Firestore will log an error to Render's console containing a
// direct link to auto-create that index — open it once and click "Create".
// Until that index exists, this sweep will fail silently (caught below) and
// do nothing; it's a backstop, so the status-poll expiry still protects you.
const SWEEP_INTERVAL_MS = 30 * 1000;
async function sweepStalePending() {
  try {
    const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - TX_TIMEOUT_MS);
    const staleSnap = await db.collection("transactions")
      .where("status", "==", "pending")
      .where("createdAt", "<=", cutoff)
      .limit(25)
      .get();
    for (const doc of staleSnap.docs) {
      await expireIfStale(doc.ref);
    }
  } catch (e) {
    // Don't let a sweep failure crash the server; just log and try again next tick.
    console.warn("Stale-transaction sweep error:", e.message);
  }
}
setInterval(sweepStalePending, SWEEP_INTERVAL_MS);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`HMK Stocks Wallet server running on port ${PORT}, firebaseReady=${firebaseReady}`);
});

