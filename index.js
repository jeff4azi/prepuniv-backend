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
  }),
);

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
    if (error || !data.user) {
      return res.status(401).json({ error: "Unauthorized: invalid token" });
    }
    req.user = data.user;
    next();
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
          if (updateErr) console.error("Webhook failed-update error:", updateErr);
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

app.post("/api/quiz/:id/attempt", authenticateRequest, async (req, res) => {
  try {
    const { id: quiz_id } = req.params;
    const { is_timed, time_allowed_seconds } = req.body;

    const { data: quiz, error: quizErr } = await supabase
      .from("quizzes")
      .select("*")
      .eq("id", quiz_id)
      .single();

    if (quizErr || !quiz) {
      return res.status(404).json({ error: "Quiz not found" });
    }

    const { data: balanceRow, error: balanceErr } = await supabase
      .from("user_balances")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    const userBalance = balanceRow?.balance || 0;

    const priceNaira = Number(quiz.price) / 100;

    if (userBalance < priceNaira) {
      return res.status(402).json({ error: "Insufficient balance" });
    }

    const payRef = "quizpay_" + crypto.randomUUID();

    const { error: payErr } = await supabase
      .from("wallet_transactions")
      .insert({
        id: "wtx_" + crypto.randomUUID(),
        user_id: req.user.id,
        amount: -priceNaira,
        type: "quiz_payment",
        status: "completed",
        reference: payRef,
        related_quiz_id: quiz.id,
      });

    if (payErr) {
      return res.status(500).json({ error: "Failed to process payment" });
    }

    const { data: attempt, error: attemptErr } = await supabase
      .from("quiz_attempts")
      .insert({
        id: "att_" + crypto.randomUUID(),
        user_id: req.user.id,
        quiz_id: quiz.id,
        is_timed: !!is_timed,
        time_allowed_seconds: is_timed
          ? time_allowed_seconds || quiz.time_allowed_seconds
          : null,
      })
      .select()
      .single();

    if (attemptErr || !attempt) {
      return res.status(500).json({ error: "Failed to create quiz attempt" });
    }

    return res.json({
      attempt_id: attempt.id,
      quiz_snapshot: attempt.quiz_snapshot || null,
      ...attempt,
    });
  } catch (err) {
    console.error("Quiz attempt error:", err);
    return res.status(500).json({ error: "Internal server error" });
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
        .in("status", ["approved", "paid", "pending"])
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

app.post(
  "/api/admin/payout-requests/:id/approve",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: payoutRequestId } = req.params;

      const { data: payoutRequest, error: prErr } = await supabase
        .from("payout_requests")
        .select("*")
        .eq("id", payoutRequestId)
        .single();

      if (prErr || !payoutRequest) {
        return res.status(404).json({ error: "Payout request not found" });
      }

      if (payoutRequest.status !== "pending") {
        return res
          .status(400)
          .json({ error: "Only pending requests can be approved" });
      }

      const { error: updateErr } = await supabase
        .from("payout_requests")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
        })
        .eq("id", payoutRequestId);

      if (updateErr) {
        return res
          .status(500)
          .json({ error: "Failed to update payout request" });
      }

      const { data: creator, error: creatorErr } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", payoutRequest.creator_id)
        .single();

      if (creatorErr || !creator) {
        return res.status(404).json({ error: "Creator profile not found" });
      }

      const bank_code = payoutRequest.bank_code || creator.bank_code;
      const account_number =
        payoutRequest.bank_account_number || creator.bank_account_number;
      const bank_account_name = creator.bank_account_name || creator.full_name;

      if (!bank_code || !account_number) {
        const failNote = "Missing bank details for creator";
        await supabase.from("wallet_transactions").insert({
          id: "wtx_" + crypto.randomUUID(),
          user_id: creator.id,
          amount: 0,
          type: "payout",
          status: "failed",
          reference: String(payoutRequestId),
        });
        await supabase
          .from("payout_requests")
          .update({ status: "failed", notes: failNote })
          .eq("id", payoutRequestId);
        return res.status(400).json({ error: failNote });
      }

      const transferRef = "payout_" + crypto.randomUUID();
      let transferSuccess = false;
      let transferMessage = "";

      try {
        const transferResp = await flutterwaveAxios.post("/transfers", {
          account_bank: bank_code,
          account_number,
          amount: payoutRequest.amount,
          currency: "NGN",
          narration: "PrepUniv payout",
          reference: transferRef,
          beneficiary_name: bank_account_name,
        });

        const transferStatus = transferResp.data?.data?.status;

        let verifiedStatus = transferStatus;
        try {
          const verifyResp = await flutterwaveAxios.get(
            `/transfers/${transferRef}`,
          );
          verifiedStatus = verifyResp.data?.data?.status || transferStatus;
          transferMessage =
            verifyResp.data?.message || transferResp.data?.message || "";
        } catch (vErr) {
          transferMessage = vErr.message;
        }

        if (
          verifiedStatus === "SUCCESSFUL" ||
          verifiedStatus === "successful" ||
          verifiedStatus === "NEW"
        ) {
          transferSuccess = true;
        } else if (verifiedStatus === "FAILED" || verifiedStatus === "failed") {
          transferSuccess = false;
          transferMessage = transferMessage || "Transfer failed";
        } else {
          transferSuccess = false;
          transferMessage = `Transfer in status: ${verifiedStatus}`;
        }
      } catch (fwErr) {
        transferSuccess = false;
        transferMessage = fwErr.response?.data?.message || fwErr.message;
      }

      if (transferSuccess) {
        await supabase.from("wallet_transactions").insert({
          id: "wtx_" + crypto.randomUUID(),
          user_id: creator.id,
          amount: -payoutRequest.amount,
          type: "payout",
          status: "completed",
          reference: String(payoutRequestId),
        });

        await supabase
          .from("payout_requests")
          .update({ status: "paid" })
          .eq("id", payoutRequestId);

        return res.json({
          ok: true,
          status: "paid",
          payout_request_id: payoutRequestId,
          transfer_reference: transferRef,
        });
      } else {
        await supabase.from("wallet_transactions").insert({
          id: "wtx_" + crypto.randomUUID(),
          user_id: creator.id,
          amount: 0,
          type: "payout",
          status: "failed",
          reference: String(payoutRequestId),
        });

        await supabase
          .from("payout_requests")
          .update({
            status: "failed",
            notes: transferMessage || "Transfer failed",
          })
          .eq("id", payoutRequestId);

        return res.json({
          ok: true,
          status: "failed",
          payout_request_id: payoutRequestId,
          message: transferMessage,
        });
      }
    } catch (err) {
      console.error("Payout approve error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

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
