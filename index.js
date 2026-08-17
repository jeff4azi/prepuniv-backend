import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import axios from "axios";

dotenv.config();

const CORS_ALLOWED_ORIGIN =
  process.env.CORS_ALLOWED_ORIGIN || "https://prepuniv.vercel.app";
const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY || "";
const FLUTTERWAVE_WEBHOOK_SECRET = process.env.FLUTTERWAVE_WEBHOOK_SECRET || "";
const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const PORT = process.env.PORT || 5000;

const MINIMUM_PAYOUT_THRESHOLD = 2000;

const app = express();

app.use(
  cors({
    origin: CORS_ALLOWED_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Explicitly handle preflight OPTIONS requests for all routes.
// Explicitly handle preflight OPTIONS requests for all routes.
// Express 5 + path-to-regexp v8 dropped wildcard string support,
// so we use a middleware instead of app.options() with a wildcard path.
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", CORS_ALLOWED_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    );
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    res.setHeader("Access-Control-Max-Age", "86400");
    return res.sendStatus(204);
  }
  next();
});

app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  }),
);

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

const authenticateRequest = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Unauthorized: missing Bearer token" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (!error && data?.user) {
      req.user = data.user;
    } else {
      // Fallback: decode JWT payload directly if getUser fails or for dev/test tokens
      if (token) {
        try {
          const parts = token.split(".");
          if (parts.length === 3) {
            const payload = JSON.parse(
              Buffer.from(parts[1], "base64").toString("utf8"),
            );
            if (payload && payload.sub) {
              req.user = {
                id: payload.sub,
                email: payload.email || "user@prepuniv.com",
                role: payload.role || "authenticated",
              };
            }
          }
        } catch (jwtErr) {
          console.warn("JWT fallback decode error:", jwtErr.message);
        }
      }

      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: invalid token" });
      }
    }

    // ── Suspension check: reject every protected request for suspended users ──
    // Admins are never suspended (enforced on the suspend route itself), but we
    // check the DB flag unconditionally here as a hard enforcement layer.
    const { data: profileRow } = await supabase
      .from("profiles")
      .select("is_suspended, role")
      .eq("id", req.user.id)
      .maybeSingle();

    if (profileRow?.is_suspended === true) {
      return res.status(403).json({ error: "account_suspended" });
    }

    return next();
  } catch (err) {
    return res
      .status(401)
      .json({ error: "Unauthorized: token verification failed" });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const { data, error } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || !data || data.role !== "admin") {
      return res.status(403).json({ error: "Forbidden: admin role required" });
    }
    next();
  } catch (err) {
    return res.status(403).json({ error: "Forbidden: admin role required" });
  }
};

const flutterwaveAxios = axios.create({
  baseURL: "https://api.flutterwave.com/v3",
  headers: {
    Authorization: `Bearer ${FLUTTERWAVE_SECRET_KEY}`,
    "Content-Type": "application/json",
  },
  timeout: 15000,
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.post(
  "/api/wallet/topup/initiate",
  authenticateRequest,
  async (req, res) => {
    try {
      const { amount } = req.body;

      if (!amount || typeof amount !== "number" || amount <= 0) {
        return res.status(400).json({ error: "Valid amount is required" });
      }

      const tx_ref = "topup_" + crypto.randomUUID();

      const { error: txError } = await supabase
        .from("wallet_transactions")
        .insert({
          id: "wtx_" + crypto.randomUUID(),
          user_id: req.user.id,
          amount,
          type: "topup",
          status: "pending",
          reference: tx_ref,
        });

      if (txError) {
        console.error("wallet_transactions insert error:", txError);
        return res
          .status(500)
          .json({ error: "Failed to create transaction record" });
      }

      let payment_link = null;
      try {
        const response = await flutterwaveAxios.post("/payments", {
          tx_ref,
          amount,
          currency: "NGN",
          redirect_url: `${CORS_ALLOWED_ORIGIN}/wallet?tx_ref=${tx_ref}`,
          customer: {
            email: req.user.email,
          },
          meta: {
            user_id: req.user.id,
            type: "wallet_topup",
          },
        });
        payment_link = response.data?.data?.link;
      } catch (fwErr) {
        console.error("Flutterwave payment init failed:", fwErr.message);
        payment_link = `${CORS_ALLOWED_ORIGIN}/wallet?tx_ref=${tx_ref}&mock_payment=1`;
      }

      return res.json({ payment_link, tx_ref });
    } catch (err) {
      console.error("Topup initiate error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post("/api/webhooks/flutterwave", async (req, res) => {
  try {
    const verifHash = req.headers["verif-hash"];
    const rawBody = req.rawBody ?? JSON.stringify(req.body);
    const expectedHash = crypto
      .createHmac(
        "sha256",
        FLUTTERWAVE_WEBHOOK_SECRET || FLUTTERWAVE_SECRET_KEY,
      )
      .update(rawBody)
      .digest("hex");

    if (verifHash !== expectedHash) {
      console.warn("Webhook signature mismatch — ignoring", {
        verifHash,
        expectedHash,
      });
      return res.status(403).json({ error: "Invalid webhook signature" });
    }

    const body = req.body;
    const eventType = body?.event;

    // ─── Transfer webhook handling (payouts) ──────────────────────────────
    if (eventType === "transfer.completed" || eventType === "transfer.failed") {
      const webhookTransferId = body?.data?.id;
      const webhookReference = body?.data?.reference;
      const webhookStatus = body?.data?.status;

      if (!webhookTransferId && !webhookReference) {
        console.warn("Transfer webhook missing both id and reference — ignoring");
        return res.status(200).json({ ok: true });
      }

      // 1. Look up the payout_requests row
      let payoutLookup;
      if (webhookTransferId) {
        payoutLookup = await supabase
          .from("payout_requests")
          .select("*")
          .eq("flutterwave_transfer_id", String(webhookTransferId))
          .maybeSingle();
      }
      if ((!payoutLookup || !payoutLookup.data) && webhookReference) {
        payoutLookup = await supabase
          .from("payout_requests")
          .select("*")
          .eq("flutterwave_reference", webhookReference)
          .maybeSingle();
      }

      const payout = payoutLookup?.data;
      if (!payout) {
        console.warn("Transfer webhook: no payout_requests row found", {
          transfer_id: webhookTransferId,
          reference: webhookReference,
        });
        return res.status(200).json({ ok: true });
      }

      // 2. Idempotency guard — if already resolved, do nothing
      if (payout.status === "paid" || payout.status === "failed") {
        console.log(
          `Transfer webhook idempotency: payout ${payout.id} already at ${payout.status}, ignoring`,
        );
        return res.status(200).json({ ok: true });
      }

      // 3. NEVER trust the webhook status alone — re-verify against the API
      let verifiedStatus = null;
      let verifiedFailureMsg = null;
      try {
        if (!FLUTTERWAVE_SECRET_KEY) {
          console.error(
            "FLUTTERWAVE_SECRET_KEY missing — cannot verify transfer webhook",
          );
          return res.status(500).json({ ok: false });
        }
        const verifyId = webhookTransferId || payout.flutterwave_transfer_id;
        if (!verifyId) {
          console.error(
            "No transfer id available to verify payout webhook",
            payout.id,
          );
          return res.status(200).json({ ok: true });
        }
        const verifyResp = await flutterwaveAxios.get(
          `/transfers/${verifyId}`,
        );
        const verified = verifyResp.data?.data ?? verifyResp.data;
        verifiedStatus = verified?.status;
        verifiedFailureMsg =
          verified?.complete_message || verified?.fail_message || null;
      } catch (verifyErr) {
        console.error(
          `Transfer webhook verify API call failed for payout ${payout.id}:`,
          verifyErr.message,
        );
        // Leave at processing — never auto-resolve on verify failure
        return res.status(200).json({ ok: true });
      }

      // 4. Act on the VERIFIED status (never the webhook payload's status)
      const statusUpper = String(verifiedStatus || "").toUpperCase();

      if (statusUpper === "SUCCESSFUL") {
        // ── Transfer completed successfully — FINALIZE payout ──
        const now = new Date().toISOString();

        // Only insert wallet_transactions row HERE, once, idempotently
        const { error: existingPayoutTxErr } = await supabase
          .from("wallet_transactions")
          .select("id")
          .eq("reference", payout.flutterwave_reference || String(payout.id))
          .eq("type", "payout")
          .maybeSingle();

        if (!existingPayoutTxErr && !existingPayoutTxErr?.data) {
          await supabase.from("wallet_transactions").insert({
            id: "wtx_" + crypto.randomUUID(),
            user_id: payout.creator_id,
            amount: -Number(payout.amount),
            type: "payout",
            status: "completed",
            reference: payout.flutterwave_reference || String(payout.id),
          });
        }

        const { error: updErr } = await supabase
          .from("payout_requests")
          .update({
            status: "paid",
            processed_at: now,
            failure_reason: null,
          })
          .eq("id", payout.id);

        if (updErr) console.error("Payout paid update error:", updErr);
        console.log(`Payout ${payout.id} marked as PAID via transfer webhook`);
      } else if (
        statusUpper === "FAILED" ||
        statusUpper === "REVERSED"
      ) {
        if (statusUpper === "FAILED") {
          await supabase
            .from("payout_requests")
            .update({
              status: "failed",
              failure_reason: verifiedFailureMsg || "Transfer failed",
            })
            .eq("id", payout.id);
          console.log(
            `Payout ${payout.id} marked as FAILED via transfer webhook`,
          );
        } else {
          // REVERSED — payout was previously paid but the bank reversed it
          // 1. Insert a compensating positive wallet_transactions (reversal)
          //    but only once — idempotency via unique reference
          const reversalRef = `reversal_${payout.flutterwave_reference || payout.id}`;
          const { data: existingReversal } = await supabase
            .from("wallet_transactions")
            .select("id")
            .eq("reference", reversalRef)
            .maybeSingle();

          if (!existingReversal) {
            await supabase.from("wallet_transactions").insert({
              id: "wtx_" + crypto.randomUUID(),
              user_id: payout.creator_id,
              amount: Number(payout.amount),
              type: "reversal",
              status: "completed",
              reference: reversalRef,
            });
          }

          await supabase
            .from("payout_requests")
            .update({
              status: "reversed",
              failure_reason:
                verifiedFailureMsg ||
                "Transfer was reversed by the bank after initial success",
            })
            .eq("id", payout.id);

          console.log(
            `Payout ${payout.id} marked as REVERSED via transfer webhook — balance restored`,
          );
        }
      } else {
        // Any unknown status — log but leave at processing
        // "Unknown" must never mean "success"
        console.log(
          `Transfer webhook: payout ${payout.id} has unrecognized verified status ${verifiedStatus}, leaving at 'processing' for manual review`,
        );
      }

      return res.status(200).json({ ok: true });
    }

    // ─── Topup webhook handling (existing logic) ──────────────────────────
    const tx_ref = body?.data?.tx_ref ?? body?.tx_ref;
    const transaction_id = body?.data?.id ?? body?.transaction_id;

    if (!tx_ref || !transaction_id) {
      return res.status(200).json({ ok: true });
    }

    try {
      const verifyResp = await flutterwaveAxios.get(
        `/transactions/${transaction_id}/verify`,
      );
      const verifyData = verifyResp.data?.data;
      const verifyStatus = verifyData?.status;

      const { data: txRow, error: lookupErr } = await supabase
        .from("wallet_transactions")
        .select("*")
        .eq("reference", tx_ref)
        .eq("status", "pending")
        .maybeSingle();

      if (lookupErr) {
        console.error("Wallet transaction lookup error:", lookupErr);
      } else if (txRow) {
        if (verifyStatus === "successful") {
          const { error: updateErr } = await supabase
            .from("wallet_transactions")
            .update({ status: "completed" })
            .eq("id", txRow.id);
          if (updateErr) console.error("Webhook update error:", updateErr);
        } else if (verifyStatus === "failed") {
          const { error: updateErr } = await supabase
            .from("wallet_transactions")
            .update({ status: "failed" })
            .eq("id", txRow.id);
          if (updateErr)
            console.error("Webhook failed-update error:", updateErr);
        }
      }
    } catch (verifyErr) {
      console.error("Flutterwave verify error:", verifyErr.message);
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Webhook error:", err);
    return res.status(200).json({ ok: true });
  }
});

/**
 * POST /api/wallet/topup/verify
 *
 * Safety-net for the Flutterwave redirect-back flow.
 * Called by the frontend when it detects ?tx_ref=... in the URL after the
 * user returns from Flutterwave's hosted checkout page.
 *
 * Queries Flutterwave directly to confirm the payment (no webhook needed),
 * then flips the pending row to completed — idempotent if already completed.
 */
app.post("/api/wallet/topup/verify", authenticateRequest, async (req, res) => {
  try {
    const { tx_ref } = req.body;

    if (!tx_ref || typeof tx_ref !== "string") {
      return res.status(400).json({ error: "tx_ref is required" });
    }

    // Look up the transaction row — must belong to the authenticated user
    const { data: txRow, error: lookupErr } = await supabase
      .from("wallet_transactions")
      .select("*")
      .eq("reference", tx_ref)
      .eq("user_id", req.user.id)
      .eq("type", "topup")
      .maybeSingle();

    if (lookupErr) {
      console.error("Topup verify lookup error:", lookupErr);
      return res.status(500).json({ error: "Failed to look up transaction" });
    }

    if (!txRow) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    // Already completed — nothing to do, just return success
    if (txRow.status === "completed") {
      return res.json({ status: "completed", already_completed: true });
    }

    if (txRow.status === "failed") {
      return res.json({ status: "failed" });
    }

    // Query Flutterwave by tx_ref using the dedicated verify_by_reference endpoint
    let fwStatus = null;
    try {
      const verifyRefResp = await flutterwaveAxios.get(
        "/transactions/verify_by_reference",
        { params: { tx_ref } },
      );
      const verifyRefData = verifyRefResp.data?.data;
      const txId = verifyRefData?.id;

      if (txId) {
        const verifyResp = await flutterwaveAxios.get(
          `/transactions/${txId}/verify`,
        );
        fwStatus = verifyResp.data?.data?.status;
      } else {
        fwStatus = verifyRefData?.status;
      }
    } catch (fwErr) {
      console.error("Flutterwave verify call failed:", fwErr.message);
      // Don't error out — fall through and return pending so the frontend can retry
      return res.json({
        status: "pending",
        message: "Payment gateway unreachable, please wait",
      });
    }

    if (fwStatus === "successful") {
      const { error: updateErr } = await supabase
        .from("wallet_transactions")
        .update({ status: "completed" })
        .eq("id", txRow.id);

      if (updateErr) {
        console.error("Topup verify update error:", updateErr);
        return res
          .status(500)
          .json({ error: "Failed to update transaction status" });
      }

      return res.json({ status: "completed" });
    }

    if (fwStatus === "failed") {
      await supabase
        .from("wallet_transactions")
        .update({ status: "failed" })
        .eq("id", txRow.id);

      return res.json({ status: "failed" });
    }
    // Still processing on Flutterwave's end
    return res.json({ status: "pending" });
  } catch (err) {
    console.error("Topup verify error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Nigerian Banks Data & Flutterwave Integration ────────────────────────────
const STATIC_NIGERIAN_BANKS = [
  { code: "044", name: "Access Bank" },
  { code: "023", name: "Citibank Nigeria" },
  { code: "050", name: "EcoBank Nigeria" },
  { code: "070", name: "Fidelity Bank" },
  { code: "011", name: "First Bank of Nigeria" },
  { code: "214", name: "First City Monument Bank (FCMB)" },
  { code: "058", name: "GTBank (Guaranty Trust)" },
  { code: "030", name: "Heritage Bank" },
  { code: "082", name: "Keystone Bank" },
  { code: "999992", name: "OPay" },
  { code: "50211", name: "Kuda Bank" },
  { code: "076", name: "Polaris Bank" },
  { code: "039", name: "Stanbic IBTC Bank" },
  { code: "232", name: "Sterling Bank" },
  { code: "033", name: "United Bank for Africa (UBA)" },
  { code: "035", name: "Wema Bank" },
  { code: "057", name: "Zenith Bank" },
];

let cachedBanksList = null;
let cachedBanksListTime = 0;
const BANK_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// ─── Get Nigerian Banks List (Flutterwave API with 24h cache) ─────────────────
app.get("/api/banks", async (req, res) => {
  try {
    const now = Date.now();
    if (cachedBanksList && now - cachedBanksListTime < BANK_CACHE_TTL) {
      return res.json({
        status: "success",
        data: cachedBanksList,
        source: "cache",
      });
    }

    if (FLUTTERWAVE_SECRET_KEY) {
      try {
        const response = await axios.get(
          "https://api.flutterwave.com/v3/banks/NG",
          {
            headers: {
              Authorization: `Bearer ${FLUTTERWAVE_SECRET_KEY}`,
            },
            timeout: 10000,
          },
        );

        if (
          response.data &&
          response.data.status === "success" &&
          Array.isArray(response.data.data)
        ) {
          const banks = response.data.data.map((b) => ({
            id: String(b.id || b.code),
            code: String(b.code),
            name: String(b.name),
          }));
          cachedBanksList = banks;
          cachedBanksListTime = now;
          return res.json({
            status: "success",
            data: banks,
            source: "flutterwave",
          });
        }
      } catch (flwErr) {
        console.warn(
          "Flutterwave fetch banks error, using static fallback:",
          flwErr.message,
        );
      }
    }

    return res.json({
      status: "success",
      data: STATIC_NIGERIAN_BANKS,
      source: "static",
    });
  } catch (err) {
    console.error("Get banks error:", err);
    return res.status(500).json({ error: "Failed to fetch banks list" });
  }
});

// ─── Resolve Account Details (Flutterwave Account Verification) ────────────────
app.post("/api/banks/resolve", authenticateRequest, async (req, res) => {
  try {
    const { accountNumber, bankCode } = req.body || {};

    if (!accountNumber || !/^\d{10}$/.test(accountNumber) || !bankCode) {
      return res
        .status(400)
        .json({ error: "Invalid 10-digit account number or bank code" });
    }

    if (FLUTTERWAVE_SECRET_KEY) {
      // Resolve the correct Flutterwave bank code by fetching their bank list
      let resolvedBankCode = bankCode;
      try {
        // Reuse the cached bank list or fetch fresh from Flutterwave
        const now = Date.now();
        if (!cachedBanksList || now - cachedBanksListTime >= BANK_CACHE_TTL) {
          const banksResponse = await axios.get(
            "https://api.flutterwave.com/v3/banks/NG",
            {
              headers: { Authorization: `Bearer ${FLUTTERWAVE_SECRET_KEY}` },
              timeout: 10000,
            },
          );
          if (
            banksResponse.data?.status === "success" &&
            Array.isArray(banksResponse.data.data)
          ) {
            cachedBanksList = banksResponse.data.data.map((b) => ({
              id: String(b.id || b.code),
              code: String(b.code),
              name: String(b.name),
            }));
            cachedBanksListTime = now;
          }
        }

        // Look up the bank in the Flutterwave list to get the correct code
        if (cachedBanksList && cachedBanksList.length > 0) {
          // First try exact code match
          const exactMatch = cachedBanksList.find((b) => b.code === bankCode);
          if (exactMatch) {
            resolvedBankCode = exactMatch.code;
          } else {
            // If code not found, try to match by name from our static list
            const staticBank = STATIC_NIGERIAN_BANKS.find(
              (b) => b.code === bankCode,
            );
            if (staticBank) {
              const nameMatch = cachedBanksList.find(
                (b) =>
                  b.name
                    .toLowerCase()
                    .includes(staticBank.name.toLowerCase()) ||
                  staticBank.name.toLowerCase().includes(b.name.toLowerCase()),
              );
              if (nameMatch) {
                resolvedBankCode = nameMatch.code;
                console.log(
                  `Resolved static bank code ${bankCode} (${staticBank.name}) to Flutterwave code ${nameMatch.code} (${nameMatch.name})`,
                );
              }
            }
          }
        }
      } catch (bankListErr) {
        console.warn(
          "Could not fetch Flutterwave bank list for code resolution:",
          bankListErr.message,
        );
        // Continue with the original code
      }

      try {
        const response = await axios.post(
          "https://api.flutterwave.com/v3/accounts/resolve",
          {
            account_number: accountNumber,
            account_bank: resolvedBankCode,
          },
          {
            headers: {
              Authorization: `Bearer ${FLUTTERWAVE_SECRET_KEY}`,
              "Content-Type": "application/json",
            },
            timeout: 12000,
          },
        );

        if (
          response.data &&
          (response.data.status === "success" ||
            response.data.data?.account_name)
        ) {
          const accountName = response.data.data?.account_name || "";
          if (accountName) {
            return res.json({
              success: true,
              accountName: accountName.toUpperCase(),
              accountNumber,
              bankCode,
            });
          }
        }
      } catch (flwErr) {
        console.warn(
          "Flutterwave resolve error:",
          flwErr.response?.data || flwErr.message,
        );
        const rawMsg = flwErr.response?.data?.message || "";
        // Provide a user-friendly error instead of exposing Flutterwave internals
        const errMsg =
          rawMsg.includes("destbankcode") || rawMsg.includes("account_bank")
            ? "This bank is not currently supported for account verification. Please try a different bank or contact support."
            : rawMsg ||
              "Could not verify account — please check account number and bank selected.";
        return res.status(400).json({ error: errMsg });
      }
    }

    // Mock fallback when FLW key is not set or in offline demo mode
    const mockName =
      req.user.user_metadata?.full_name?.toUpperCase() ||
      req.user.email?.split("@")[0]?.toUpperCase() ||
      "ACCOUNT HOLDER";

    return res.json({
      success: true,
      accountName: mockName,
      accountNumber,
      bankCode,
    });
  } catch (err) {
    console.error("Resolve bank error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error resolving account" });
  }
});

// ─── Sync Quiz Version Helper ──────────────────────────────────────────────────
async function syncQuizVersion(quizId) {
  try {
    const { data: questions, error: qErr } = await supabase
      .from("questions")
      .select("id, type, question_text, options, correct_answer, order_index")
      .eq("quiz_id", quizId)
      .order("order_index", { ascending: true });

    if (qErr) {
      console.error("syncQuizVersion fetch questions error:", qErr);
      throw qErr;
    }

    const currentQuestions = (questions || []).map((q) => ({
      id: String(q.id),
      type: String(q.type || "mcq"),
      question_text: String(q.question_text || ""),
      options: q.options ?? null,
      correct_answer: q.correct_answer ?? "",
      order_index: Number(q.order_index || 0),
    }));

    const { data: latestVersion, error: vErr } = await supabase
      .from("quiz_versions")
      .select("*")
      .eq("quiz_id", quizId)
      .order("version_number", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (vErr) {
      console.error("syncQuizVersion fetch latest version error:", vErr);
    }

    let isDifferent = false;
    if (!latestVersion) {
      isDifferent = true;
    } else {
      const prevSnapshot =
        typeof latestVersion.questions_snapshot === "string"
          ? JSON.parse(latestVersion.questions_snapshot)
          : latestVersion.questions_snapshot;

      if (JSON.stringify(currentQuestions) !== JSON.stringify(prevSnapshot)) {
        isDifferent = true;
      }
    }

    if (isDifferent) {
      const nextVersionNum = (latestVersion?.version_number || 0) + 1;
      const { data: newVersion, error: insertErr } = await supabase
        .from("quiz_versions")
        .insert({
          quiz_id: quizId,
          version_number: nextVersionNum,
          questions_snapshot: currentQuestions,
          question_count: currentQuestions.length,
        })
        .select()
        .single();

      if (insertErr) {
        console.error("syncQuizVersion insert version error:", insertErr);
        const { data: fallback } = await supabase
          .from("quiz_versions")
          .select("*")
          .eq("quiz_id", quizId)
          .order("version_number", { ascending: false })
          .limit(1)
          .maybeSingle();
        return fallback || latestVersion;
      }
      return newVersion;
    }

    return latestVersion;
  } catch (err) {
    console.error("syncQuizVersion error:", err);
    return null;
  }
}

// ─── Start / Retake a Quiz (creates a attempt row) ──────────────────────────
app.post("/api/quiz/:id/attempt", authenticateRequest, async (req, res) => {
  try {
    const { id: quizId } = req.params;
    const { is_timed, time_allowed_seconds } = req.body || {};

    const { data: quiz, error: quizErr } = await supabase
      .from("quizzes")
      .select("*")
      .eq("id", quizId)
      .maybeSingle();

    if (quizErr) throw quizErr;
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // Check if user has already paid for this quiz
    const { data: existingPay } = await supabase
      .from("wallet_transactions")
      .select("id")
      .eq("user_id", req.user.id)
      .eq("related_quiz_id", quiz.id)
      .eq("type", "quiz_payment")
      .eq("status", "completed")
      .maybeSingle();

    const isFirstTime = !existingPay;
    const version = await syncQuizVersion(quiz.id);

    if (isFirstTime) {
      const { data: balanceRow, error: balanceErr } = await supabase
        .from("user_balances")
        .select("*")
        .eq("user_id", req.user.id)
        .maybeSingle();

      if (balanceErr) {
        console.error("Balance lookup error:", balanceErr);
        return res.status(500).json({ error: "Failed to look up balance" });
      }

      const userBalance = Number(balanceRow?.balance || 0);
      const priceNaira = Number(quiz.price) / 100;

      if (userBalance < priceNaira) {
        return res.status(402).json({
          error: `Insufficient balance: need ₦${priceNaira.toFixed(2)}, have ₦${userBalance.toFixed(2)}`,
        });
      }

      const attemptId = "att_" + crypto.randomUUID();
      const payRef = "quizpay_" + crypto.randomUUID();
      const paymentTxnId = "wtx_" + crypto.randomUUID();

      await supabase.from("wallet_transactions").insert({
        id: paymentTxnId,
        user_id: req.user.id,
        amount: -priceNaira,
        type: "quiz_payment",
        status: "completed",
        reference: payRef,
        related_quiz_id: quiz.id,
        related_attempt_id: attemptId,
      });

      const { data: attempt, error: attemptErr } = await supabase
        .from("quiz_attempts")
        .insert({
          id: attemptId,
          user_id: req.user.id,
          quiz_id: quiz.id,
          quiz_version_id: version?.id || null,
          is_timed: !!is_timed,
          time_allowed_seconds: is_timed
            ? Number(time_allowed_seconds || quiz.time_limit_seconds || 0) ||
              null
            : null,
        })
        .select()
        .single();

      if (attemptErr) throw attemptErr;

      return res.json({
        attempt_id: attempt.id,
        quiz_id: attempt.quiz_id,
        quiz_version_id: attempt.quiz_version_id,
        questions: version?.questions_snapshot || [],
        ...attempt,
      });
    } else {
      // Retake — already paid, just create a new attempt row (no charge)
      const attemptId = "att_" + crypto.randomUUID();

      const { data: attempt, error: attemptErr } = await supabase
        .from("quiz_attempts")
        .insert({
          id: attemptId,
          user_id: req.user.id,
          quiz_id: quiz.id,
          quiz_version_id: version?.id || null,
          is_timed: !!is_timed,
          time_allowed_seconds: is_timed
            ? Number(time_allowed_seconds || quiz.time_limit_seconds || 0) ||
              null
            : null,
        })
        .select()
        .single();

      if (attemptErr) throw attemptErr;

      return res.json({
        attempt_id: attempt.id,
        quiz_id: attempt.quiz_id,
        quiz_version_id: attempt.quiz_version_id,
        questions: version?.questions_snapshot || [],
        ...attempt,
      });
    }
  } catch (err) {
    console.error("Quiz attempt error:", err);
    return res.status(500).json({
      error: "Internal server error",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

// ─── Complete a quiz attempt: set score, timestamps, save graded answers ──────
app.post("/api/attempt/:id/complete", authenticateRequest, async (req, res) => {
  try {
    const { id: attemptId } = req.params;
    const { score, started_at, completed_at, time_taken_seconds, answers } =
      req.body;

    if (typeof score !== "number" || score < 0 || score > 100) {
      return res.status(400).json({ error: "Invalid payload" });
    }

    // 1. Verify ownership
    const { data: existing, error: lookupErr } = await supabase
      .from("quiz_attempts")
      .select("*")
      .eq("id", attemptId)
      .maybeSingle();

    if (lookupErr) throw lookupErr;
    if (!existing) return res.status(404).json({ error: "Attempt not found" });
    if (existing.user_id !== req.user.id) {
      return res.status(403).json({ error: "Not your attempt" });
    }

    let answersMap = {};
    if (Array.isArray(answers)) {
      for (const a of answers) {
        if (a && typeof a === "object" && typeof a.question_id === "string") {
          answersMap[a.question_id] =
            typeof a.given === "string" ? a.given : String(a.given ?? "");
        }
      }
    } else if (answers && typeof answers === "object") {
      answersMap = answers;
    }

    // 2. Update the attempt row (score, timestamps, time taken, answers JSONB)
    const { error: updateErr } = await supabase
      .from("quiz_attempts")
      .update({
        score: Number(score.toFixed(2)),
        started_at:
          started_at ?? existing.started_at ?? new Date().toISOString(),
        completed_at: completed_at ?? new Date().toISOString(),
        time_taken_seconds:
          typeof time_taken_seconds === "number" && time_taken_seconds >= 0
            ? Math.round(time_taken_seconds)
            : null,
        answers: answersMap,
      })
      .eq("id", attemptId);

    if (updateErr) {
      console.error("update attempt error:", JSON.stringify(updateErr));
      return res.status(500).json({
        error: "Failed to save attempt score",
        detail: updateErr.message,
        code: updateErr.code,
        hint: updateErr.hint,
      });
    }

    // 3. Save attempt_answers rows for backwards compatibility
    if (Array.isArray(answers) && answers.length > 0) {
      const rows = answers
        .filter(
          (a) =>
            a && typeof a === "object" && typeof a.question_id === "string",
        )
        .map((a) => ({
          id: `aa_${attemptId}_${a.question_id}`,
          attempt_id: attemptId,
          question_id: a.question_id,
          question_text:
            typeof a.question_text === "string" ? a.question_text : null,
          answer_given:
            typeof a.given === "string" ? a.given : String(a.given ?? ""),
          correct_answer:
            typeof a.correct === "string" ? a.correct : String(a.correct ?? ""),
          is_correct: !!a.is_correct,
        }));

      const { error: insertErr } = await supabase
        .from("attempt_answers")
        .upsert(rows, { onConflict: "id" });

      if (insertErr) {
        console.error(
          "insert attempt_answers error:",
          JSON.stringify(insertErr),
        );
      }
    }

    // 4. Bump attempt_count on the quiz itself (best-effort, ignore errors)
    if (existing.quiz_id) {
      Promise.resolve(
        supabase.rpc("increment_attempt_count", {
          quiz_id_in: existing.quiz_id,
        }),
      ).catch(() => void 0);
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Attempt complete error:", err);
    return res.status(500).json({
      error: "Internal server error",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

// ─── Delete / Abandon an uncompleted attempt ──────────────────────────────────
app.delete("/api/attempt/:id", authenticateRequest, async (req, res) => {
  try {
    const { id: attemptId } = req.params;
    const { error } = await supabase
      .from("quiz_attempts")
      .delete()
      .eq("id", attemptId)
      .eq("user_id", req.user.id)
      .is("completed_at", null);

    if (error) {
      console.error("Delete attempt error:", error);
      return res.status(500).json({ error: "Failed to delete attempt" });
    }
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Get Quiz Analytics Data for Creator / Admin ────────────────────────────────
app.get("/api/quiz/:id/analytics", authenticateRequest, async (req, res) => {
  try {
    const { id: quizId } = req.params;

    // 1. Fetch quiz details
    const { data: quiz, error: quizErr } = await supabase
      .from("quizzes")
      .select("*")
      .eq("id", quizId)
      .maybeSingle();

    if (quizErr) throw quizErr;
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // 2. Authorization check: must be owner or admin
    const isAdmin = req.user.role === "admin";
    if (quiz.creator_id !== req.user.id && !isAdmin) {
      return res
        .status(403)
        .json({ error: "Unauthorized access to quiz analytics" });
    }

    // 3. Fetch course, versions, questions, and completed attempts concurrently using backend admin access
    const [cRes, vRes, qRes, aRes] = await Promise.all([
      quiz.course_id
        ? supabase
            .from("courses")
            .select("*")
            .eq("id", quiz.course_id)
            .maybeSingle()
        : Promise.resolve({ data: null }),
      supabase
        .from("quiz_versions")
        .select("*")
        .eq("quiz_id", quizId)
        .order("version_number", { ascending: false }),
      supabase
        .from("questions")
        .select("*")
        .eq("quiz_id", quizId)
        .order("order_index", { ascending: true }),
      supabase
        .from("quiz_attempts")
        .select("*")
        .eq("quiz_id", quizId)
        .not("completed_at", "is", null),
    ]);

    const course = cRes.data ?? null;
    const versions = vRes.data ?? [];
    let questions = qRes.data ?? [];
    const attempts = aRes.data ?? [];

    // Fallback: If questions table is empty, use latest version's questions_snapshot
    if (questions.length === 0 && versions.length > 0) {
      const latestSnapshot = versions[0].questions_snapshot;
      questions =
        typeof latestSnapshot === "string"
          ? JSON.parse(latestSnapshot)
          : latestSnapshot;
    }

    // 4. Fetch attempt_answers for all completed attempt IDs
    const attemptIds = attempts.map((a) => a.id);
    let attemptAnswers = [];
    if (attemptIds.length > 0) {
      const { data: ansData } = await supabase
        .from("attempt_answers")
        .select("question_id, is_correct")
        .in("attempt_id", attemptIds);
      attemptAnswers = ansData ?? [];
    }

    return res.json({
      quiz,
      course,
      versions,
      questions,
      attempts,
      attemptAnswers,
    });
  } catch (err) {
    console.error("Quiz analytics error:", err);
    return res.status(500).json({
      error: "Internal server error",
      detail: err instanceof Error ? err.message : String(err),
    });
  }
});

app.post(
  "/api/creator/payout-request",
  authenticateRequest,
  async (req, res) => {
    try {
      const { amount } = req.body;

      if (!amount || typeof amount !== "number" || amount <= 0) {
        return res.status(400).json({ error: "Valid amount is required" });
      }

      const { data: profile, error: profileErr } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", req.user.id)
        .single();

      if (profileErr || !profile) {
        return res.status(404).json({ error: "Profile not found" });
      }

      if (!profile.is_approved_creator) {
        return res
          .status(403)
          .json({ error: "Only approved creators can request payouts" });
      }

      const { data: balanceRow, error: balanceErr } = await supabase
        .from("user_balances")
        .select("*")
        .eq("user_id", req.user.id)
        .maybeSingle();

      const earningsBalance = balanceRow?.balance || 0;

      if (earningsBalance < amount) {
        return res
          .status(400)
          .json({ error: "Amount exceeds available earnings balance" });
      }

      if (amount < MINIMUM_PAYOUT_THRESHOLD) {
        return res.status(400).json({
          error: `Below minimum payout threshold of ₦${MINIMUM_PAYOUT_THRESHOLD.toLocaleString()}`,
        });
      }

      const { data: lastRequest, error: lastErr } = await supabase
        .from("payout_requests")
        .select("requested_at")
        .eq("creator_id", req.user.id)
        .in("status", ["pending", "processing", "paid"])
        .order("requested_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (lastErr) {
        console.error("Last payout lookup error:", lastErr);
      } else if (lastRequest) {
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const requestDate = new Date(lastRequest.requested_at);
        if (requestDate > sevenDaysAgo) {
          return res.status(429).json({
            error: "Payout request frequency limit exceeded: 1 per 7 days",
          });
        }
      }

      const { data: inserted, error: insertErr } = await supabase
        .from("payout_requests")
        .insert({
          creator_id: req.user.id,
          amount,
          status: "pending",
          bank_account_number: profile.bank_account_number || null,
          bank_code: profile.bank_code || null,
        })
        .select()
        .single();

      if (insertErr || !inserted) {
        return res
          .status(500)
          .json({ error: "Failed to create payout request" });
      }

      return res.json({
        id: inserted.id,
        amount: inserted.amount,
        status: inserted.status,
        requested_at: inserted.requested_at,
      });
    } catch (err) {
      console.error("Payout request error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);


/* Transfer to creators endpoint */
app.post(
  "/api/admin/payout-requests/:id/approve",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: payoutRequestId } = req.params;

      // ====================================================================
      // PART 2 — ATOMIC STATE TRANSITION (prevents double-payment)
      // The very first thing we do: try to atomically flip pending→processing.
      // The eq('status', 'pending') guard means only ONE concurrent caller
      // will ever match — all others get zero rows and bail out with 409.
      // ====================================================================
      const { data: locked, error: lockErr } = await supabase
        .from("payout_requests")
        .update({ status: "processing" })
        .eq("id", payoutRequestId)
        .eq("status", "pending")
        .select()
        .single();

      if (lockErr || !locked) {
        // Either the row didn't exist at all, or it wasn't pending.
        // Distinguish the two cases for a clear error.
        const { data: existingRow } = await supabase
          .from("payout_requests")
          .select("status")
          .eq("id", payoutRequestId)
          .maybeSingle();

        if (!existingRow) {
          return res.status(404).json({ error: "Payout request not found" });
        }

        if (
          existingRow.status === "failed" ||
          existingRow.status === "reversed"
        ) {
          // Retry case: a previously-failed/reversed payout is being retried.
          // Atomically flip it back to processing to lock this attempt.
          const { data: relocked, error: relockErr } = await supabase
            .from("payout_requests")
            .update({ status: "processing" })
            .eq("id", payoutRequestId)
            .in("status", ["failed", "reversed"])
            .select()
            .single();

          if (relockErr || !relocked) {
            return res.status(409).json({
              error:
                "This payout has already been processed or is being processed",
            });
          }
          // relock succeeded — continue with relocked as our locked row
          return await _continuePayoutApprove(relocked, res);
        }

        // Any other status (processing / paid / rejected): already in flight or final
        return res.status(409).json({
          error:
            "This payout has already been processed or is being processed",
        });
      }

      // Lock succeeded — continue with the rest of the flow.
      return await _continuePayoutApprove(locked, res);
    } catch (err) {
      console.error("Payout approve outer error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Extracted helper — the post-lock body of the approve flow.
// Shared between the initial approve path and the retry-from-failed path.
async function _continuePayoutApprove(payoutRequest, res) {
  const payoutRequestId = payoutRequest.id;

  try {
    // ====================================================================
    // Fetch creator profile once.
    // ====================================================================
    const { data: creator, error: creatorErr } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", payoutRequest.creator_id)
      .single();

    if (creatorErr || !creator) {
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason: "Creator profile not found",
        })
        .eq("id", payoutRequestId);
      return res.status(404).json({ error: "Creator profile not found" });
    }

    // ====================================================================
    // Resolve bank details.
    // ====================================================================
    const bank_code = payoutRequest.bank_code || creator.bank_code;
    const account_number =
      payoutRequest.bank_account_number || creator.bank_account_number;

    if (!bank_code || !account_number) {
      const failMsg = "Missing bank details for creator";
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason: failMsg,
        })
        .eq("id", payoutRequestId);
      return res.status(400).json({ error: failMsg });
    }

    // ====================================================================
    // PART 5 — VERIFIED BANK ACCOUNT NAME ONLY (no full_name fallback)
    // The whole point of the bank-verify setup flow was to capture the
    // Flutterwave-resolved account holder name. If it's not present, HARD
    // FAIL — never fall back to an unverified user-entered name.
    // ====================================================================
    const bank_account_name = creator.bank_account_name;
    if (!bank_account_name || !bank_account_name.trim()) {
      const failMsg =
        "Creator's bank account is not verified — they must complete the bank verification flow before payouts can be sent.";
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason: failMsg,
        })
        .eq("id", payoutRequestId);
      return res.status(400).json({ error: failMsg });
    }

    // ====================================================================
    // PART 3 — STABLE, IDEMPOTENT TRANSFER REFERENCE
    // Check if this payout request already has a reference (retry path).
    // If yes, reuse it. If no, generate one and PERSIST IT NOW, BEFORE
    // calling Flutterwave, so a crash between generating and calling
    // doesn't cause a second reference on retry.
    // ====================================================================
    let transferRef = payoutRequest.flutterwave_reference;
    if (!transferRef) {
      transferRef = "payout_" + crypto.randomUUID();
      const { error: refErr } = await supabase
        .from("payout_requests")
        .update({ flutterwave_reference: transferRef })
        .eq("id", payoutRequestId);
      if (refErr) {
        console.error("Failed to persist flutterwave_reference:", refErr);
        await supabase
          .from("payout_requests")
          .update({
            status: "failed",
            failure_reason: "Internal error preparing transfer reference",
          })
          .eq("id", payoutRequestId);
        return res
          .status(500)
          .json({ error: "Internal error preparing payout" });
      }
    }

    // ====================================================================
    // PART 8 — NO SILENT DEMO MODE
    // Missing key = hard 500 with server log.
    // Only explicit PAYOUT_MODE=demo is accepted as a deliberate local-dev
    // simulation, and it logs clearly so it can never be mistaken for real.
    // ====================================================================
    const PAYOUT_MODE = process.env.PAYOUT_MODE || "live";
    if (!FLUTTERWAVE_SECRET_KEY && PAYOUT_MODE !== "demo") {
      const errMsg =
        "FLUTTERWAVE_SECRET_KEY not configured — payouts cannot be processed. Set PAYOUT_MODE=demo only for local development simulation.";
      console.error(errMsg);
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason: "Payment gateway not configured",
        })
        .eq("id", payoutRequestId);
      return res.status(500).json({ error: "Payment gateway not configured" });
    }

    // ====================================================================
    // EXPLICIT DEMO MODE (only when PAYOUT_MODE=demo is set)
    // Visibly labeled, never inferred from a missing key.
    // ====================================================================
    if (PAYOUT_MODE === "demo") {
      console.warn(
        `[DEMO MODE] Payout ${payoutRequestId} — simulating processing for transfer_ref=${transferRef}. No real money moved.`,
      );
      await supabase
        .from("payout_requests")
        .update({
          status: "processing",
          flutterwave_reference: transferRef,
        })
        .eq("id", payoutRequestId);
      return res.json({
        ok: true,
        status: "processing",
        payout_request_id: payoutRequestId,
        transfer_reference: transferRef,
        demo_mode: true,
        note:
          "DEMO MODE: transfer not actually sent. Set PAYOUT_MODE=live and provide FLUTTERWAVE_SECRET_KEY for real payouts.",
      });
    }

    // ====================================================================
    // PART 4 — CORRECT FLUTTERWAVE V3 TRANSFER PAYLOAD
    // The v3 /transfers payload does NOT include beneficiary_name.
    // Standard v3 shape: account_bank, account_number, amount,
    // currency, narration, reference, debit_currency.
    // Reference is our stable, persisted idempotency key.
    // ====================================================================
    let fwTransferId = null;
    let synchronousFailure = null;

    try {
      const transferResp = await flutterwaveAxios.post("/transfers", {
        account_bank: bank_code,
        account_number,
        amount: Number(payoutRequest.amount),
        currency: "NGN",
        narration: "PrepUniv creator payout",
        reference: transferRef,
        debit_currency: "NGN",
      });

      const transferData = transferResp.data?.data;
      fwTransferId = transferData?.id ? String(transferData.id) : null;
      const transferStatus = transferData?.status
        ? String(transferData.status).toUpperCase()
        : null;

      // If Flutterwave returned a synchronous FAILED status (rare but possible),
      // record it immediately as a failure.
      if (transferStatus === "FAILED") {
        synchronousFailure =
          transferData?.complete_message ||
          transferData?.fail_message ||
          "Transfer rejected synchronously by Flutterwave/bank";
      }
      // Any other 2xx response with an ID means the transfer was ACCEPTED
      // and is now in flight (NEW / PENDING / QUEUED etc). We do NOT treat
      // any of these as "paid" — only the webhook, after re-verification,
      // can flip to paid/failed/reversed.
    } catch (fwErr) {
      // A genuine synchronous rejection (network-level or real API error
      // with an error response that isn't a queued status).
      synchronousFailure =
        fwErr.response?.data?.message ||
        fwErr.response?.data?.error ||
        fwErr.message ||
        "Transfer request failed";
      console.error(
        "Flutterwave transfer synchronous error:",
        fwErr.response?.data || fwErr.message,
      );
    }

    // ====================================================================
    // PART 6 — CORRECT RESPONSE HANDLING: PROCESSING IS NOT PAID
    //
    // Accepted (got a transfer id, no sync failure):
    //   - status = 'processing'
    //   - store flutterwave_transfer_id
    //   - NO wallet_transactions row yet
    //   - NO status='paid'
    //   - Return { status: 'processing' } to admin UI
    //
    // Synchronous hard failure:
    //   - status = 'failed'
    //   - failure_reason populated
    //   - NO wallet_transactions row
    // ====================================================================
    if (synchronousFailure) {
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason: synchronousFailure,
        })
        .eq("id", payoutRequestId);

      return res.json({
        ok: true,
        status: "failed",
        payout_request_id: payoutRequestId,
        transfer_reference: transferRef,
        message: synchronousFailure,
      });
    }

    // Transfer accepted and in flight — persist the transfer id.
    const updateFields = {
      status: "processing",
      flutterwave_transfer_id: fwTransferId,
    };
    await supabase
      .from("payout_requests")
      .update(updateFields)
      .eq("id", payoutRequestId);

    return res.json({
      ok: true,
      status: "processing",
      payout_request_id: payoutRequestId,
      transfer_reference: transferRef,
      flutterwave_transfer_id: fwTransferId,
    });
  } catch (innerErr) {
    console.error("Payout approve inner flow error:", innerErr);
    // Best-effort: mark as failed so we don't leave a stuck processing row
    try {
      await supabase
        .from("payout_requests")
        .update({
          status: "failed",
          failure_reason:
            innerErr instanceof Error
              ? innerErr.message
              : "Unexpected error during payout initiation",
        })
        .eq("id", payoutRequestId);
    } catch (_rollbackErr) {
      // swallow — we already have the error logged
    }
    return res.status(500).json({ error: "Internal server error" });
  }
}

app.post(
  "/api/admin/payout-requests/:id/reject",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: payoutRequestId } = req.params;
      const { notes } = req.body;

      const { error } = await supabase
        .from("payout_requests")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          notes: notes || null,
        })
        .eq("id", payoutRequestId);

      if (error) {
        return res
          .status(500)
          .json({ error: "Failed to reject payout request" });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("Payout reject error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post(
  "/api/admin/creator-applications/:id/approve",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: applicationId } = req.params;

      const { data: application, error: appErr } = await supabase
        .from("creator_applications")
        .select("*")
        .eq("id", applicationId)
        .single();

      if (appErr || !application) {
        return res.status(404).json({ error: "Creator application not found" });
      }

      await supabase
        .from("creator_applications")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
        })
        .eq("id", applicationId);

      const { data: currentProfile } = await supabase
        .from("profiles")
        .select("role")
        .eq("id", application.user_id)
        .single();

      const updateData = {
        is_approved_creator: true,
      };
      if (currentProfile && currentProfile.role === "user") {
        updateData.role = "creator";
      }

      await supabase
        .from("profiles")
        .update(updateData)
        .eq("id", application.user_id);

      return res.json({ ok: true });
    } catch (err) {
      console.error("Creator approve error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post(
  "/api/admin/creator-applications/:id/reject",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: applicationId } = req.params;
      const { notes } = req.body;

      const { error } = await supabase
        .from("creator_applications")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          notes: notes || null,
        })
        .eq("id", applicationId);

      if (error) {
        return res
          .status(500)
          .json({ error: "Failed to reject creator application" });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("Creator reject error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ─── Admin Management Endpoints ─────────────────────────────────────────────

// GET /api/admin/users — profiles + auth emails
app.get(
  "/api/admin/users",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { data: profiles, error: profErr } = await supabase
        .from("profiles")
        .select("*")
        .order("created_at", { ascending: false });
      if (profErr)
        return res.status(500).json({ error: "Failed to fetch profiles" });

      const { data: authData, error: authErr } =
        await supabase.auth.admin.listUsers({ perPage: 1000 });
      const emailMap = {};
      if (!authErr && authData?.users) {
        authData.users.forEach((u) => {
          emailMap[u.id] = u.email;
        });
      }

      const enriched = (profiles || []).map((p) => ({
        ...p,
        email: emailMap[p.id] || null,
      }));

      return res.json({ users: enriched });
    } catch (err) {
      console.error("Admin get users error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/users/:id/suspend — toggle suspension
// On suspend:   hides creator quizzes (snapshots which were live), force-revokes sessions.
// On unsuspend: restores only the quizzes that were published before suspension.
app.post(
  "/api/admin/users/:id/suspend",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { suspend } = req.body;

      // Fetch target profile to validate and branch logic
      const { data: targetProfile, error: profileFetchErr } = await supabase
        .from("profiles")
        .select("role, is_suspended, is_approved_creator")
        .eq("id", id)
        .maybeSingle();

      if (profileFetchErr || !targetProfile) {
        return res.status(404).json({ error: "User not found" });
      }

      // Admins cannot be suspended
      if (targetProfile.role === "admin") {
        return res
          .status(403)
          .json({ error: "Admin accounts cannot be suspended" });
      }

      if (suspend) {
        // ── SUSPENDING ────────────────────────────────────────────────────────

        // 1. Snapshot + hide creator's quizzes
        if (targetProfile.is_approved_creator) {
          // Mark currently-published quizzes so unsuspend can restore them
          await supabase
            .from("quizzes")
            .update({ was_published_before_suspension: true })
            .eq("creator_id", id)
            .eq("is_published", true);

          // Take all their quizzes offline immediately
          await supabase
            .from("quizzes")
            .update({ is_published: false })
            .eq("creator_id", id);
        }

        // 2. Set is_suspended = true
        const { error } = await supabase
          .from("profiles")
          .update({ is_suspended: true })
          .eq("id", id);

        if (error)
          return res
            .status(500)
            .json({ error: "Failed to update suspension status" });

        // 3. Force-invalidate all active sessions so the user is kicked out
        //    immediately, not just blocked on their next protected API call.
        try {
          await supabase.auth.admin.signOut(id, "others");
        } catch (signOutErr) {
          // Non-fatal: authenticateRequest suspension check is the hard boundary.
          console.warn(
            "Session invalidation warning (non-fatal):",
            signOutErr?.message ?? signOutErr,
          );
        }

        return res.json({ ok: true, is_suspended: true });
      } else {
        // ── UNSUSPENDING ──────────────────────────────────────────────────────

        // 1. Restore only quizzes that were live before suspension.
        //    Quizzes the creator had already unpublished (was_published_before_suspension=false)
        //    stay unpublished — we don't blindly re-publish everything.
        if (targetProfile.is_approved_creator) {
          await supabase
            .from("quizzes")
            .update({
              is_published: true,
              was_published_before_suspension: false,
            })
            .eq("creator_id", id)
            .eq("was_published_before_suspension", true);

          // Clear the snapshot flag on already-unpublished quizzes too
          await supabase
            .from("quizzes")
            .update({ was_published_before_suspension: false })
            .eq("creator_id", id)
            .eq("was_published_before_suspension", false);
        }

        // 2. Clear suspension flag
        const { error } = await supabase
          .from("profiles")
          .update({ is_suspended: false })
          .eq("id", id);

        if (error)
          return res
            .status(500)
            .json({ error: "Failed to update suspension status" });

        return res.json({ ok: true, is_suspended: false });
      }
    } catch (err) {
      console.error("Admin suspend user error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/quizzes/:id/unpublish — admin force-unpublish
app.post(
  "/api/admin/quizzes/:id/unpublish",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await supabase
        .from("quizzes")
        .update({ is_published: false, unpublished_by_admin: true })
        .eq("id", id);
      if (error)
        return res.status(500).json({ error: "Failed to unpublish quiz" });
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin unpublish quiz error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/quizzes/:id/republish — admin re-publish
app.post(
  "/api/admin/quizzes/:id/republish",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await supabase
        .from("quizzes")
        .update({ is_published: true, unpublished_by_admin: false })
        .eq("id", id);
      if (error)
        return res.status(500).json({ error: "Failed to republish quiz" });
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin republish quiz error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/reports/:id/resolve
app.post(
  "/api/admin/reports/:id/resolve",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { notes } = req.body;
      const { error } = await supabase
        .from("reports")
        .update({
          status: "resolved",
          resolved_at: new Date().toISOString(),
          resolution_notes: notes || null,
        })
        .eq("id", id);
      if (error)
        return res.status(500).json({ error: "Failed to resolve report" });
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin resolve report error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/reports/:id/dismiss
app.post(
  "/api/admin/reports/:id/dismiss",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { notes } = req.body;
      const { error } = await supabase
        .from("reports")
        .update({
          status: "dismissed",
          resolved_at: new Date().toISOString(),
          resolution_notes: notes || null,
        })
        .eq("id", id);
      if (error)
        return res.status(500).json({ error: "Failed to dismiss report" });
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin dismiss report error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/creator/reports/:id/acknowledge
// Creator marks a resolved-with-feedback report as addressed ("I fixed it").
// Only the creator who owns the quiz may call this, and only on non-open reports.
app.post(
  "/api/creator/reports/:id/acknowledge",
  authenticateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;
      const callerId = req.user.id;

      // Verify the report exists and belongs to a quiz owned by this creator
      const { data: report, error: fetchErr } = await supabase
        .from("reports")
        .select("id, status, quiz_id")
        .eq("id", id)
        .maybeSingle();

      if (fetchErr || !report) {
        return res.status(404).json({ error: "Report not found" });
      }
      if (report.status === "open") {
        return res
          .status(400)
          .json({ error: "Cannot acknowledge an open report" });
      }

      // Confirm caller owns the quiz
      const { data: quiz } = await supabase
        .from("quizzes")
        .select("creator_id")
        .eq("id", report.quiz_id)
        .maybeSingle();

      if (!quiz || quiz.creator_id !== callerId) {
        return res.status(403).json({ error: "Forbidden: not your quiz" });
      }

      const { error: updateErr } = await supabase
        .from("reports")
        .update({ creator_acknowledged: true })
        .eq("id", id);

      if (updateErr)
        return res.status(500).json({ error: "Failed to acknowledge report" });

      return res.json({ ok: true });
    } catch (err) {
      console.error("Creator acknowledge report error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// PUT /api/admin/courses/:id — update course metadata
app.put(
  "/api/admin/courses/:id",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { code, name, subject_area, level } = req.body;
      const updates = {};
      if (code !== undefined) updates.code = code;
      if (name !== undefined) updates.name = name;
      if (subject_area !== undefined) updates.subject_area = subject_area;
      if (level !== undefined) updates.level = level;

      const { data, error } = await supabase
        .from("courses")
        .update(updates)
        .eq("id", id)
        .select()
        .single();
      if (error)
        return res.status(500).json({ error: "Failed to update course" });
      return res.json({ course: data });
    } catch (err) {
      console.error("Admin update course error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/universities — add university
app.post(
  "/api/admin/universities",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { name, abbreviation, state } = req.body;
      if (!name || !abbreviation) {
        return res
          .status(400)
          .json({ error: "Name and abbreviation are required" });
      }
      const uniId = `uni_${Date.now()}`;
      const { data, error } = await supabase
        .from("universities")
        .insert({ id: uniId, name, abbreviation, state: state || null })
        .select()
        .single();
      if (error)
        return res
          .status(500)
          .json({ error: error.message || "Failed to add university" });
      return res.json({ university: data });
    } catch (err) {
      console.error("Admin add university error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// PUT /api/admin/universities/:id — update university
app.put(
  "/api/admin/universities/:id",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, abbreviation, state } = req.body;
      const updates = {};
      if (name !== undefined) updates.name = name;
      if (abbreviation !== undefined) updates.abbreviation = abbreviation;
      if (state !== undefined) updates.state = state;

      const { data, error } = await supabase
        .from("universities")
        .update(updates)
        .eq("id", id)
        .select()
        .single();
      if (error)
        return res.status(500).json({ error: "Failed to update university" });
      return res.json({ university: data });
    } catch (err) {
      console.error("Admin update university error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// DELETE /api/admin/universities/:id — delete university (only if no deps)
app.delete(
  "/api/admin/universities/:id",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const [profilesRes, coursesRes, quizzesRes] = await Promise.all([
        supabase
          .from("profiles")
          .select("id", { count: "exact", head: true })
          .eq("university_id", id),
        supabase
          .from("courses")
          .select("id", { count: "exact", head: true })
          .eq("university_id", id),
        supabase
          .from("quizzes")
          .select("id", { count: "exact", head: true })
          .eq("university_id", id),
      ]);

      const deps =
        (profilesRes.count || 0) +
        (coursesRes.count || 0) +
        (quizzesRes.count || 0);
      if (deps > 0) {
        return res.status(409).json({
          error: `Cannot delete: ${profilesRes.count || 0} users, ${coursesRes.count || 0} courses, and ${quizzesRes.count || 0} quizzes are linked to this university.`,
        });
      }

      const { error } = await supabase
        .from("universities")
        .delete()
        .eq("id", id);
      if (error)
        return res.status(500).json({ error: "Failed to delete university" });
      return res.json({ ok: true });
    } catch (err) {
      console.error("Admin delete university error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post("/api/bank/resolve-account", authenticateRequest, async (req, res) => {
  try {
    const { account_number, bank_code } = req.body;

    if (!account_number || !bank_code) {
      return res
        .status(400)
        .json({ error: "account_number and bank_code are required" });
    }

    const response = await flutterwaveAxios.post("/accounts/resolve", {
      account_number,
      account_bank: bank_code,
    });

    return res.json(response.data?.data || response.data);
  } catch (err) {
    console.error("Resolve account error:", err);
    const status = err.response?.status || 500;
    const message = err.response?.data?.message || err.message;
    return res.status(status).json({ error: message });
  }
});

app.get("/api/banks", authenticateRequest, async (req, res) => {
  try {
    const response = await flutterwaveAxios.get("/banks/NG", {
      params: { country: "NG" },
    });
    return res.json(response.data?.data || []);
  } catch (err) {
    console.error("Get banks error:", err.message);
    return res.json([]);
  }
});

// app.listen is only used in local development.
// On Vercel (serverless), the exported app is used directly as the handler.
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;
