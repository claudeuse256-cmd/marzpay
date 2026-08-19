
// server.js — HMK Stocks Wallet backend (deploy on Render)
// Host: https://marzpay.onrender.com
//
// REQUIRED ENVIRONMENT VARIABLES (set these in Render dashboard, never in code):
//   FIREBASE_SERVICE_ACCOUNT   -> full JSON of your Firebase service account key, as ONE LINE string
//                                 (must be a service account for the "whealthsphere" Firebase project)
//   MARZPAY_API_KEY            -> your MarzPay API Key (marz_...)
//   MARZPAY_API_SECRET         -> your MarzPay API Secret
//   MARZPAY_BASE_URL           -> https://wallet.wearemarz.com/api/v1
//   WEBHOOK_SECRET              -> a random string you choose, used to verify MarzPay webhook calls (optional but recommended)
//   PORT                        -> Render sets this automatically

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const fetch = require("node-fetch");
const FormData = require("form-data");
const { randomUUID } = require("crypto");

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
app.use(express.json());

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
// This runs from two places, and both share this one function so there is
// never a double-refund race between them:
//   1. GET /api/transaction/:reference/status — checked every time the
//      client polls, so expiry is enforced even if this Render instance was
//      asleep the whole time and only just woke up to serve the poll.
//   2. A setInterval sweep below, as a backstop for whenever the instance
//      happens to be awake on its own.
const TX_TIMEOUT_MS = 60 * 1000; // 60 seconds

async function expireIfStale(txRef) {
  return db.runTransaction(async (t) => {
    const snap = await t.get(txRef);
    if (!snap.exists) return null;
    const tx = snap.data();

    if (tx.status !== "pending") return tx; // already resolved, nothing to do

    const createdMs = tx.createdAt && tx.createdAt.toMillis ? tx.createdAt.toMillis() : 0;
    const ageMs = Date.now() - createdMs;
    if (!createdMs || ageMs < TX_TIMEOUT_MS) return tx; // not stale yet

    const updated = {
      status: "failed",
      failReason: "Timed out waiting for network confirmation (60s).",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (tx.type === "withdraw") {
      // Refund the reserved balance since the payout never confirmed.
      const userRef = db.collection("users").doc(tx.uid);
      t.update(userRef, { balance: admin.firestore.FieldValue.increment(tx.amount) });
    }
    t.update(txRef, updated);

    return { ...tx, ...updated, status: "failed" };
  });
}

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
    const { phone, amount } = req.body;
    const cleanPhone = normalizePhone(phone);
    const amt = Number(amount);

    if (!cleanPhone || !isValidAmount(amt)) {
      return res.status(400).json({ success: false, error: "Valid phone and amount (min 500 UGX) are required." });
    }

    const userRef = db.collection("users").doc(req.uid);
    const txRef = db.collection("transactions").doc();
    const reference = randomUUID(); // MarzPay requires a valid UUID v4 reference

    // Transaction-safe balance check + reservation
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
        phone: cleanPhone,
        status: "pending",
        reference,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    const withdrawForm = new FormData();
    withdrawForm.append("phone_number", cleanPhone);
    withdrawForm.append("amount", String(amt));
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

    res.json({ success: true, reference, message: "Withdrawal submitted for processing." });
  } catch (err) {
    console.error("Withdraw error:", err);
    res.status(400).json({ success: false, error: err.message || "Server error while processing withdrawal." });
  }
});

// ---------- TRANSACTION STATUS (polled by wallet.html) ----------
// The client polls this every few seconds after submitting a deposit/withdraw
// in automatic mode. This is also where stale "pending" transactions actually
// get expired to "failed" — see expireIfStale() above for why that lives here
// rather than only in a background timer.
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
app.post("/webhook/marzpay", async (req, res) => {
  try {
    // Optional shared-secret check if you configure WEBHOOK_SECRET in Render
    // and MarzPay supports a signing header — adjust header name to match their docs.
    if (process.env.WEBHOOK_SECRET) {
      const incomingSecret = req.headers["x-webhook-secret"];
      if (incomingSecret !== process.env.WEBHOOK_SECRET) {
        return res.status(401).json({ success: false, error: "Invalid webhook secret." });
      }
    }

    // MarzPay's webhook payload nests everything under `transaction`, e.g.:
    // { "event_type": "collection.completed", "transaction": { "reference": "...", "status": "completed" }, "collection": {...} }
    const eventType = req.body.event_type;
    const transaction = req.body.transaction || {};
    const reference = transaction.reference;
    const status = transaction.status;

    if (!reference) {
      console.warn("Webhook missing transaction.reference. Full body:", JSON.stringify(req.body));
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
    // since MarzPay documents this as the authoritative "final status" signal; fall back to transaction.status.
    const normalizedEvent = String(eventType || "").toLowerCase();
    const normalizedStatus = String(status || "").toLowerCase();
    const isSuccess = normalizedEvent.endsWith(".completed") || normalizedStatus === "completed" || normalizedStatus === "successful";
    const isFailed = normalizedEvent.endsWith(".failed") || normalizedEvent.endsWith(".cancelled")
      || normalizedStatus === "failed" || normalizedStatus === "cancelled";

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
    } else {
      // Unrecognized status — log and leave pending for manual review
      await txDoc.ref.update({
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        webhookPayload: req.body,
        note: "Unrecognized webhook status: " + status
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).json({ success: false, error: "Webhook processing error." });
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
    if (!transactionId || !["completed", "failed", "pending"].includes(newStatus)) {
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

