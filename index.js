import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import axios from "axios";
import { HttpsProxyAgent } from "https-proxy-agent";
import { calculatePaymentProcessingFee, roundToTwoDecimals } from "./feeCalculator.js";
import webpush from "web-push";

dotenv.config();

const CORS_ALLOWED_ORIGIN = process.env.CORS_ALLOWED_ORIGIN;
if (!CORS_ALLOWED_ORIGIN) {
  console.error(
    "FATAL: CORS_ALLOWED_ORIGIN is not configured. Set it explicitly in environment variables before starting the server.",
  );
  process.exit(1);
}
const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY || "";
const FLUTTERWAVE_WEBHOOK_SECRET = process.env.FLUTTERWAVE_WEBHOOK_SECRET;
if (!FLUTTERWAVE_WEBHOOK_SECRET) {
  console.error(
    "WARNING: FLUTTERWAVE_WEBHOOK_SECRET is not configured — webhook signature verification cannot proceed. Webhook calls will be rejected until this is set.",
  );
}
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.warn("WARNING: VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not configured — push notifications will be skipped.");
}
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    "mailto:support@prepuniv.com",
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
}
const PUSH_ENABLED = !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const PORT = process.env.PORT || 5000;

const MINIMUM_PAYOUT_THRESHOLD = 2000;

const ALLOWED_NOTIFICATION_TYPES = new Set([
  "topup_completed", "topup_partial", "topup_failed",
  "quiz_purchase_confirmed", "admin_broadcast",
  "payout_requested", "payout_paid", "payout_failed", "payout_reversed",
  "new_report_on_quiz", "quiz_suspended",
  "creator_application_approved", "creator_application_rejected",
  "new_report_submitted", "new_creator_application", "payout_requested_pending_review",
]);

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
      const AUTH_BYPASS_MODE = process.env.AUTH_BYPASS_MODE;
      if (AUTH_BYPASS_MODE === "dev_only" && token) {
        try {
          const parts = token.split(".");
          if (parts.length === 3) {
            const payload = JSON.parse(
              Buffer.from(parts[1], "base64").toString("utf8"),
            );
            if (payload && payload.sub) {
              console.warn(
                `[AUTH_BYPASS_MODE=dev_only] Accepting unverified JWT for sub=${payload.sub}. This MUST NOT be enabled in production.`,
              );
              req.user = {
                id: payload.sub,
                email: payload.email || "user@prepuniv.com",
                role: payload.role || "authenticated",
              };
            }
          }
        } catch (jwtErr) {
          console.warn("AUTH_BYPASS_MODE decode error:", jwtErr.message);
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

const fixieUrl = process.env.FIXIE_URL;
const transferProxyAgent = fixieUrl ? new HttpsProxyAgent(fixieUrl) : undefined;

const flutterwaveTransferAxios = axios.create({
  baseURL: "https://api.flutterwave.com/v3",
  headers: {
    Authorization: `Bearer ${FLUTTERWAVE_SECRET_KEY}`,
    "Content-Type": "application/json",
  },
  timeout: 15000,
  ...(transferProxyAgent
    ? { httpsAgent: transferProxyAgent, proxy: false }
    : {}),
});

console.log(
  fixieUrl
    ? "Creator transfer calls routed via Fixie static IP"
    : "Creator transfer calls using direct connection (no FIXIE_URL set — set this before re-enabling Flutterwave IP whitelisting)",
);

// ─── Notifications + Web Push helpers ──────────────────────────────────────

function validateNotificationType(type) {
  if (!ALLOWED_NOTIFICATION_TYPES.has(type)) {
    throw new Error(`Invalid notification type: ${type}`);
  }
  return type;
}

async function insertNotification({ userId, type, title, body, data = {}, createdBy = null }) {
  try {
    validateNotificationType(type);
    const { error } = await supabase.from("notifications").insert({
      user_id: userId,
      type,
      title,
      body,
      data,
      created_by: createdBy,
    });
    if (error) {
      console.error(`[notifications] insert failed for user=${userId} type=${type}:`, error.message);
      return null;
    }
    return true;
  } catch (err) {
    console.error(`[notifications] insert error for user=${userId}:`, err.message);
    return null;
  }
}

async function sendPushToUser(userId, { title, body, data = {} }) {
  if (!PUSH_ENABLED) return;
  try {
    const { data: subs, error } = await supabase
      .from("push_subscriptions")
      .select("*")
      .eq("user_id", userId);
    if (error || !subs || subs.length === 0) return;
    await sendPushBatch(subs, { title, body, data });
  } catch (err) {
    console.error(`[push] sendPushToUser error for user=${userId}:`, err.message);
  }
}

async function sendPushBatch(subscriptionRows, { title, body, data = {} }) {
  if (!PUSH_ENABLED) return { sent: 0, failed: 0, pruned: 0 };
  let sent = 0;
  let failed = 0;
  const toPrune = [];
  const payload = JSON.stringify({ title, body, data });

  for (const sub of subscriptionRows) {
    if (!sub.endpoint || !sub.p256dh || !sub.auth) continue;
    try {
      await webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        payload
      );
      sent++;
      supabase
        .from("push_subscriptions")
        .update({ last_seen_at: new Date().toISOString() })
        .eq("id", sub.id)
        .catch((e) => console.warn("push_subscriptions last_seen update failed:", e.message));
    } catch (err) {
      const status = err?.statusCode;
      if (status === 410 || status === 404) {
        toPrune.push(sub.id);
      } else {
        failed++;
        console.warn(`[push] send failed for endpoint=${sub.endpoint.slice(0,40)}...:`, err?.message || String(err));
      }
    }
  }
  if (toPrune.length) {
    try {
      await supabase.from("push_subscriptions").delete().in("id", toPrune);
    } catch (e) {
      console.error("[push] prune failed:", e.message);
    }
  }
  return { sent, failed, pruned: toPrune.length };
}

async function processBroadcastBatch(broadcastId, batchSize = 200) {
  const { data: bc, error: bcErr } = await supabase
    .from("notification_broadcasts")
    .update({ status: "processing" })
    .eq("id", broadcastId)
    .in("status", ["pending", "processing"])
    .select()
    .maybeSingle();
  if (bcErr || !bc) return { error: bcErr?.message || "broadcast not found" };

  try {
    const cursor = bc.last_processed_user_id;
    let query = supabase.from("profiles").select("id").order("id", { ascending: true }).limit(batchSize);
    if (bc.target === "user" && bc.target_user_id) {
      query = query.eq("id", bc.target_user_id);
    } else if (cursor) {
      query = query.gt("id", cursor);
    }

    let processedInThisBatch = 0;
    const { data: users, error: usersErr } = await query;
    if (usersErr) throw usersErr;
    if (!users || users.length === 0) {
      await supabase.from("notification_broadcasts").update({
        status: "done",
        completed_at: new Date().toISOString(),
      }).eq("id", broadcastId);
      return { done: true, total_processed: bc.processed_count };
    }

    const userIds = users.map((u) => u.id);
    const notifRows = userIds.map((uid) => ({
      user_id: uid,
      type: "admin_broadcast",
      title: bc.title,
      body: bc.body,
      data: bc.data,
      created_by: bc.created_by,
    }));
    const { error: notifErr } = await supabase.from("notifications").insert(notifRows);
    if (notifErr) console.error("[broadcast] notifications insert failed:", notifErr.message);

    try {
      const { data: subs } = await supabase
        .from("push_subscriptions")
        .select("*")
        .in("user_id", userIds);
      if (subs && subs.length) {
        await sendPushBatch(subs, { title: bc.title, body: bc.body, data: bc.data });
      }
    } catch (pushErr) {
      console.error("[broadcast] push send failed:", pushErr.message);
    }

    processedInThisBatch = userIds.length;
    const newProcessedCount = (bc.processed_count || 0) + processedInThisBatch;
    const lastUserId = bc.target === "user" ? null : users[users.length - 1].id;
    const isDone = bc.target === "user" || processedInThisBatch < batchSize;

    const finalTotal = bc.total_recipients || 0;
    const { error: updErr } = await supabase
      .from("notification_broadcasts")
      .update({
        processed_count: newProcessedCount,
        last_processed_user_id: lastUserId,
        total_recipients: finalTotal,
        status: isDone ? "done" : "processing",
        completed_at: isDone ? new Date().toISOString() : null,
      })
      .eq("id", broadcastId);
    if (updErr) console.error("[broadcast] update failed:", updErr.message);

    return {
      done: isDone,
      processed_count: newProcessedCount,
      total_recipients: finalTotal,
    };
  } catch (err) {
    console.error(`[broadcast] batch process failed for ${broadcastId}:`, err.message);
    return { error: err.message };
  }
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ─── Push notification routes ────────────────────────────────────────────────────
app.get("/api/push/vapid-public-key", (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.json({ enabled: false });
  res.json({ enabled: true, publicKey: VAPID_PUBLIC_KEY });
});

app.get("/api/push/vapid-key", (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.json({ enabled: false });
  res.json({ enabled: true, public_key: VAPID_PUBLIC_KEY });
});

// POST /api/push/subscribe — user saves new push subscription for self
app.post("/api/push/subscribe", authenticateRequest, async (req, res) => {
  try {
    const { endpoint, p256dh, auth } = req.body || {};
    if (!endpoint || !p256dh || !auth) {
      return res.status(400).json({ error: "endpoint, p256dh, auth are required" });
    }
    const ua = typeof req.headers["user-agent"] || null;
    const now = new Date().toISOString();
    const { data: existing } = await supabase
      .from("push_subscriptions")
      .select("id")
      .eq("endpoint", endpoint)
      .maybeSingle();
    if (existing) {
      await supabase.from("push_subscriptions")
        .update({ user_agent: ua, last_seen_at: now })
        .eq("id", existing.id);
      return res.json({ ok: true, updated: true });
    }
    const { error } = await supabase.from("push_subscriptions").insert({
      user_id: req.user.id, endpoint, p256dh, auth, user_agent: ua, last_seen_at: now,
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true, created: true });
  } catch (err) {
    console.error("[push] subscribe error:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api/push/unsubscribe — user deletes their own push subscription
app.delete("/api/push/unsubscribe", authenticateRequest, async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: "endpoint required" });
    await supabase.from("push_subscriptions")
      .delete()
      .eq("endpoint", endpoint)
      .eq("user_id", req.user.id);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[push] unsubscribe error:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/push/unsubscribe — same as DELETE, alias for clients that don't support DELETE with body
app.post("/api/push/unsubscribe", authenticateRequest, async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: "endpoint required" });
    await supabase.from("push_subscriptions")
      .delete()
      .eq("endpoint", endpoint)
      .eq("user_id", req.user.id);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[push] unsubscribe error:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ── wrap helper that does BOTH DB insert + push send (for backend-originated notifications only)
async function notifyUser(userId, { type, title, body, data = {}, createdBy = null }) {
  await insertNotification({ userId, type, title, body, data, createdBy });
  const ndata = (typeof data === "string" ? JSON.parse(data) : data);
  await sendPushToUser(userId, { title, body, data: { ...ndata, url: ndata?.url } });
}

// ─── Admin broadcast routes ────────────────────────────────────────────────
app.post(
  "/api/admin/notifications/broadcast",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { title, body, data, target, targetUserId } = req.body || {};
      if (!title || typeof title !== "string") {
        return res.status(400).json({ error: "title is required" });
      }
      if (!target || !["all", "user"].includes(target)) {
        return res.status(400).json({ error: "target must be 'all' or 'user'" });
      }
      if (target === "user" && !targetUserId) {
        return res.status(400).json({ error: "targetUserId required for user target" });
      }
      // Compute total_recipients count
      let total = 0;
      if (target === "all") {
        const { count, error: cntErr } = await supabase
          .from("profiles")
          .select("*", { count: "exact", head: true });
        if (cntErr) console.warn("broadcast count warn:", cntErr.message);
        total = count || 0;
      } else {
        total = 1;
      }
      const { data: bc, error: bcErr } = await supabase
        .from("notification_broadcasts")
        .insert({
          title,
          body: body || null,
          data: data || {},
          target,
          target_user_id: target === "user" ? targetUserId : null,
          created_by: req.user.id,
          total_recipients: total,
        })
        .select()
        .single();
      if (bcErr) return res.status(500).json({ error: bcErr.message });
      // Kick off first batch synchronously (serverless-safe — no background thread pool).
      processBroadcastBatch(bc.id, 200).catch((e) => console.error("broadcast kickoff failed:", e?.message || e));
      return res.status(202).json({ ok: true, broadcast: bc });
    } catch (err) {
      console.error("broadcast create error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// GET /api/admin/notifications/broadcasts/:id — poll broadcast status
app.get(
  "/api/admin/notifications/broadcasts/:id",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { data: bc, error } = await supabase
        .from("notification_broadcasts")
        .select("*")
        .eq("id", id)
        .maybeSingle();
      if (error) return res.status(500).json({ error: error.message });
      if (!bc) return res.status(404).json({ error: "Broadcast not found" });
      // serverless — re-trigger next batch if still processing/pending (idempotent kicker)
      if (bc.status === "processing" || bc.status === "pending") {
        processBroadcastBatch(bc.id, 200).catch((e) => console.warn("status poll kick error:", e?.message || e));
      }
      return res.json(bc);
    } catch (err) {
      console.error("broadcast status error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// POST /api/admin/notifications/broadcasts/:id/continue — manually kick another batch
app.post(
  "/api/admin/notifications/broadcasts/:id/continue",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const result = await processBroadcastBatch(id, 200);
      return res.json(result);
    } catch (err) {
      console.error("broadcast continue error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// GET /api/admin/notifications/broadcasts — list recent broadcasts
app.get(
  "/api/admin/notifications/broadcasts",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || "20", 10), 100);

      const { data, error } = await supabase
        .from("notification_broadcasts")
        .select(`
          id,
          title,
          target,
          target_user_id,
          total_recipients,
          processed_count,
          status,
          created_at,
          completed_at
        `)
        .order("created_at", { ascending: false })
        .limit(limit);

      if (error) {
        console.error("broadcasts list query failed:", error.message);
        return res.status(500).json({ error: "Failed to load broadcasts" });
      }

      // Collect target_user_ids for lookup
      const targetUserIds = (data || [])
        .filter((r) => r.target === "user" && r.target_user_id)
        .map((r) => r.target_user_id);

      let userNameMap = {};
      if (targetUserIds.length > 0) {
        const { data: profileRows } = await supabase
          .from("profiles")
          .select("id, full_name")
          .in("id", targetUserIds);
        if (profileRows) {
          profileRows.forEach((p) => {
            userNameMap[p.id] = p.full_name;
          });
        }
      }

      const broadcasts = (data || []).map((r) => ({
        id: r.id,
        title: r.title,
        target: r.target,
        target_user_name:
          r.target === "user" && r.target_user_id
            ? userNameMap[r.target_user_id] || null
            : null,
        total_recipients: r.total_recipients,
        processed_count: r.processed_count,
        status: r.status,
        created_at: r.created_at,
        completed_at: r.completed_at,
      }));

      return res.json({ broadcasts });
    } catch (err) {
      console.error("broadcasts list error:", err.message);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

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
          gross_amount: amount,
          net_amount: amount,
          processing_fee: 0,
          vat_fee: 0,
          platform_fee: 0,
          fee_is_estimated: false,
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
        const { data: profile } = await supabase
          .from("profiles")
          .select("full_name")
          .eq("id", req.user.id)
          .maybeSingle();

        const customerName =
          profile?.full_name ||
          req.user.user_metadata?.full_name ||
          req.user.user_metadata?.name ||
          "";

        const response = await flutterwaveAxios.post("/payments", {
          tx_ref,
          amount,
          currency: "NGN",
          redirect_url: `${CORS_ALLOWED_ORIGIN}/wallet?tx_ref=${tx_ref}`,
          customer: {
            email: req.user.email,
            ...(customerName ? { name: customerName } : {}),
          },
          customizations: {
            title: "PREPUNIV Wallet Top-up",
            description: "Account balance top-up",
          },
          meta: {
            user_id: req.user.id,
            type: "wallet_topup",
          },
        });
        payment_link = response.data?.data?.link;
        if (!payment_link) {
          throw new Error("Flutterwave response missing payment link");
        }
      } catch (fwErr) {
        console.error("Flutterwave payment init failed:", fwErr.message);
        await supabase
          .from("wallet_transactions")
          .update({ status: "failed" })
          .eq("reference", tx_ref);
        return res.status(502).json({
          error: "Unable to start payment, please try again",
        });
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
    if (!FLUTTERWAVE_WEBHOOK_SECRET) {
      console.error(
        "Webhook rejected: FLUTTERWAVE_WEBHOOK_SECRET is not configured — cannot verify webhook signatures.",
      );
      return res.status(500).json({
        error:
          "Webhook signature verification not configured. Set FLUTTERWAVE_WEBHOOK_SECRET.",
      });
    }

    const verifHash = req.headers["verif-hash"];
    if (!verifHash || verifHash !== FLUTTERWAVE_WEBHOOK_SECRET) {
      console.warn("Webhook signature mismatch — ignoring", {
        verifHash,
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
        console.warn(
          "Transfer webhook missing both id and reference — ignoring",
        );
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
        const verifyResp = await flutterwaveTransferAxios.get(
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
        notifyUser(payout.creator_id, {
          type: "payout_paid",
          title: "Payout sent",
          body: `Your ₦${Number(payout.amount).toLocaleString()} payout has been sent to your bank account.`,
          data: { url: "/creator/payouts", payout_id: payout.id },
        }).catch(() => {});
      } else if (statusUpper === "FAILED" || statusUpper === "REVERSED") {
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
          notifyUser(payout.creator_id, {
            type: "payout_failed",
            title: "Payout failed",
            body: `Your ₦${Number(payout.amount).toLocaleString()} payout failed: ${verifiedFailureMsg || "Transfer failed"}`,
            data: { url: "/creator/payouts" },
          }).catch(() => {});
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
          notifyUser(payout.creator_id, {
            type: "payout_reversed",
            title: "Payout reversed",
            body: `Your ₦${Number(payout.amount).toLocaleString()} payout was reversed by the bank. The funds have been returned to your balance.`,
            data: { url: "/creator/payouts" },
          }).catch(() => {});
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

    // ─── Topup webhook handling ──────────────────────────
    const tx_ref = body?.data?.tx_ref ?? body?.tx_ref;
    const transaction_id = body?.data?.id ?? body?.transaction_id;

    if (tx_ref) {
      try {
        let verifyData = null;
        let verifyStatus = null;

        if (transaction_id) {
          const verifyResp = await flutterwaveAxios.get(
            `/transactions/${transaction_id}/verify`,
          );
          verifyData = verifyResp.data?.data;
          verifyStatus = verifyData?.status;
        } else {
          const verifyRefResp = await flutterwaveAxios.get(
            "/transactions/verify_by_reference",
            { params: { tx_ref } },
          );
          verifyData = verifyRefResp.data?.data;
          verifyStatus = verifyData?.status;
        }

        const { data: txRow, error: lookupErr } = await supabase
          .from("wallet_transactions")
          .select("*")
          .eq("reference", tx_ref)
          .in("status", ["pending", "partial"])
          .maybeSingle();

        if (lookupErr) {
          console.error("Wallet transaction lookup error:", lookupErr);
        } else if (txRow) {
          if (verifyStatus === "successful") {
            await completeTopupTransaction(txRow, verifyData);
          } else if (verifyStatus === "failed" || verifyStatus === "cancelled") {
            const { error: updateErr } = await supabase
              .from("wallet_transactions")
              .update({ status: "failed" })
              .eq("id", txRow.id)
              .eq("status", "pending");
            if (updateErr)
              console.error("Webhook failed-update error:", updateErr);
            notifyUser(txRow.user_id, { type: "topup_failed", title: "Top-up failed", body: "Your top-up could not be completed. Please try again or contact support.", data: { url: "/wallet" } }).catch(() => {});
          }
        }
      } catch (verifyErr) {
        console.error("Flutterwave verify error:", verifyErr.message);
      }
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Webhook error:", err);
    return res.status(200).json({ ok: true });
  }
});

/**
 * Idempotent topup completion helper.
 * Calculates platform processing fees, records fee accounting on the transaction row,
 * and performs an atomic status transition from 'pending' to 'completed'.
 */
async function completeTopupTransaction(txRow, verifyData = null) {
  if (!txRow) return { success: false, error: "Transaction required" };

  if (txRow.status === "failed") {
    return { status: "failed", already_failed: true };
  }

  // ── Amount / currency guard ────────────────────────────────────────────
  // Flutterwave can return status "successful" for a bank-transfer charge
  // even when the amount actually received is LESS than what was requested
  // — this is documented, expected behaviour on their side, not a bug.
  // See: https://developer.flutterwave.com/v3.0/docs/transaction-verification
  // Never credit the user's requested amount without checking what
  // Flutterwave actually confirms was charged/received.
  const expectedAmount = Number(txRow.gross_amount || txRow.amount || 0);
  const confirmedAmount = Number(
    verifyData?.charged_amount ?? verifyData?.amount ?? 0,
  );
  const confirmedCurrency = verifyData?.currency;

  if (confirmedCurrency && confirmedCurrency !== "NGN") {
    console.error(
      `Topup ${txRow.id}: currency mismatch — expected NGN, got ${confirmedCurrency}. Leaving unresolved for manual review.`,
    );
    return { status: "currency_mismatch", success: false };
  }

  if (confirmedAmount + 0.01 < expectedAmount) {
    // Underpayment — do NOT credit the wallet. Record what actually came in
    // and flag it distinctly, rather than silently staying "pending"
    // forever or crediting the full requested amount.
    const { error: partialErr } = await supabase
      .from("wallet_transactions")
      .update({
        status: "partial",
        amount_received: confirmedAmount,
      })
      .eq("id", txRow.id)
      .in("status", ["pending", "partial"]);

    if (partialErr) {
      console.error("Partial topup update error:", partialErr);
      return { success: false, error: partialErr.message };
    }

    console.warn(
      `Topup ${txRow.id}: underpayment detected — expected ${expectedAmount}, received ${confirmedAmount}. Wallet NOT credited.`,
    );
    const partRet = { status: "partial", expectedAmount, confirmedAmount };
    notifyUser(txRow.user_id, {
      type: "topup_partial",
      title: "Top-up pending review",
      body: `We received ₦${Number(confirmedAmount || 0).toLocaleString()} of the requested ₦${Number(expectedAmount || 0).toLocaleString()}. Your wallet will be credited once the difference is settled.`,
      data: { url: "/wallet" },
    }).catch(() => {});
    return partRet;
  }

  const actualGatewayFee = verifyData?.app_fee ?? verifyData?.fee ?? null;
  const amountSettled = verifyData?.amount_settled ?? verifyData?.settled_amount ?? null;
  const grossAmount = Number(txRow.gross_amount || txRow.amount || 0);
  const feeBreakdown = calculatePaymentProcessingFee(
    grossAmount,
    actualGatewayFee,
    amountSettled,
  );

  if (txRow.status === "completed") {
    // If fee accounting was inaccurate (e.g. platform_fee recorded as 2 instead of 2.15), update fee fields
    if (
      Number(txRow.platform_fee) !== feeBreakdown.totalPlatformFee ||
      Number(txRow.net_amount) !== feeBreakdown.netAmount
    ) {
      await supabase
        .from("wallet_transactions")
        .update({
          gross_amount: feeBreakdown.grossAmount,
          processing_fee: feeBreakdown.processingFee,
          vat_fee: feeBreakdown.vatOnProcessingFee,
          platform_fee: feeBreakdown.totalPlatformFee,
          net_amount: feeBreakdown.netAmount,
          fee_rate: feeBreakdown.feeRate,
          fee_is_estimated: feeBreakdown.feeIsEstimated,
        })
        .eq("id", txRow.id);
    }
    return { status: "completed", already_completed: true };
  }

  const { data: updatedTx, error: updateErr } = await supabase
    .from("wallet_transactions")
    .update({
      status: "completed",
      gross_amount: feeBreakdown.grossAmount,
      processing_fee: feeBreakdown.processingFee,
      vat_fee: feeBreakdown.vatOnProcessingFee,
      platform_fee: feeBreakdown.totalPlatformFee,
      net_amount: feeBreakdown.netAmount,
      fee_rate: feeBreakdown.feeRate,
      fee_is_estimated: feeBreakdown.feeIsEstimated,
    })
    .eq("id", txRow.id)
    .eq("status", "pending")
    .select()
    .maybeSingle();

  if (updateErr) {
    console.error("Topup transaction completion update error:", updateErr);
    return { success: false, error: updateErr.message };
  }

  if (updatedTx) {
    notifyUser(txRow.user_id, {
      type: "topup_completed",
      title: "Top-up successful",
      body: `Your wallet has been credited with ₦${Number(txRow.amount || 0).toLocaleString()}.`,
      data: { url: "/wallet", tx_ref: txRow.reference },
    }).catch(() => {});
  }

  return {
    status: "completed",
    already_completed: !updatedTx,
    tx: updatedTx || txRow,
  };
}

// How long a topup is allowed to sit "pending" before we stop waiting on
// Flutterwave and just call it dead. Applies unconditionally — see below.
const TOPUP_STALE_MS = 20 * 60 * 1000; // 20 minutes

/**
 * Resolves ONE pending/partial topup row against Flutterwave.
 *
 * The timestamp-based staleness check (`created_at` vs now) is the primary
 * safety net and is UNCONDITIONAL: it applies no matter what happened with
 * the Flutterwave call — whether it explicitly said "pending", returned
 * something we didn't recognize, or threw an error of any kind (timeout,
 * 404, 500, rate limit, a malformed reference on an old test row, etc).
 *
 * The previous version of this logic only had a staleness fallback for one
 * narrow case (a 404 specifically, and only after 10 minutes) buried inside
 * a catch block. Any other kind of Flutterwave error — which is exactly
 * what tends to happen on old/abandoned references — fell through a
 * different code path that returned "pending" unconditionally and never
 * looked at the age at all. That's why rows sat pending for days even after
 * clicking "Sync & Reconcile": the age check was never being reached.
 *
 * This function is now the single place that talks to Flutterwave for a
 * pending topup, used by both the admin reconcile sweep and the user-facing
 * /api/wallet/topup/verify endpoint, so the two can't drift out of sync
 * with each other again.
 */
async function resolveTopupAgainstFlutterwave(txRow) {
  const ageMs = Date.now() - new Date(txRow.created_at).getTime();
  const tx_ref = txRow.reference;

  let fwStatus = null;
  let verifyData = null;

  if (tx_ref) {
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
        verifyData = verifyResp.data?.data;
        fwStatus = verifyData?.status;
      } else {
        verifyData = verifyRefData;
        fwStatus = verifyRefData?.status;
      }
    } catch (err) {
      // Deliberately not branching on err.response?.status here — ANY
      // failure to get a definitive answer from Flutterwave falls through
      // to the unconditional age check below, not just 404s.
      console.error(
        `Topup resolve: Flutterwave verify failed for ${tx_ref}:`,
        err.message,
      );
    }
  }

  if (fwStatus === "successful") {
    return { outcome: "completed", verifyData };
  }

  if (fwStatus && fwStatus !== "pending") {
    // Flutterwave gave us an explicit terminal status that isn't
    // "successful" (e.g. cancelled, failed).
    return { outcome: "failed", verifyData };
  }

  // fwStatus is null (verify call errored or returned nothing usable) or
  // literally "pending" — either way, check the clock.
  if (ageMs > TOPUP_STALE_MS) {
    return { outcome: "stale", verifyData };
  }

  return { outcome: "pending", verifyData };
}

/**
 * On-demand Topup Reconciliation Helper.
 *
 * NOTE: this server runs on a serverless platform, so there is no
 * persistent process for setInterval()/setTimeout() to run in — each
 * invocation is a fresh, short-lived instance, so a background timer
 * either never fires or fires unreliably. Instead, this function is
 * invoked opportunistically whenever a human actually looks at topup
 * data:
 *   - the admin dashboard triggers it (throttled) on every load
 *   - a user's own pending/partial rows get individually re-verified
 *     by /api/wallet/topup/verify whenever they view their wallet
 *     (see the WalletPage polling loop on the frontend)
 *
 * `throttleMs` guards against re-running this full sweep (which calls
 * out to Flutterwave once per pending row) on every single page load —
 * across concurrent serverless invocations it only actually runs at
 * most once per `throttleMs`, tracked in the `reconciliation_state`
 * table. Pass `force: true` to bypass the throttle (used by the manual
 * "Sync & Reconcile" admin button).
 *
 * For transactions nobody ever revisits (user closes the tab and never
 * comes back, admin never opens the dashboard), this on-demand approach
 * alone won't catch them. Point an external scheduler — Vercel Cron,
 * Supabase pg_cron, or any hosted cron — at POST /api/admin/topups/reconcile
 * every few minutes as a backstop; serverless just can't schedule its own.
 */
async function reconcilePendingTopups({
  force = false,
  throttleMs = 60 * 1000,
} = {}) {
  if (!FLUTTERWAVE_SECRET_KEY) return { reconciled: 0, errors: 0 };

  if (!force) {
    const { data: state } = await supabase
      .from("reconciliation_state")
      .select("last_run_at")
      .eq("id", "topup_reconcile")
      .maybeSingle();

    if (state) {
      const sinceLastRun = Date.now() - new Date(state.last_run_at).getTime();
      if (sinceLastRun < throttleMs) {
        return { skipped: true, reason: "throttled" };
      }
    }
  }

  // Claim this run immediately (before doing any work) so concurrent
  // serverless invocations don't all pile in and hammer Flutterwave.
  await supabase.from("reconciliation_state").upsert({
    id: "topup_reconcile",
    last_run_at: new Date().toISOString(),
  });

  try {
    // 1. Reconcile pending topups
    const { data: pendingTxns, error } = await supabase
      .from("wallet_transactions")
      .select("*")
      .eq("type", "topup")
      .eq("status", "pending")
      .order("created_at", { ascending: true });

    let reconciledCount = 0;
    let errorCount = 0;

    if (!error && pendingTxns && pendingTxns.length > 0) {
      for (const txRow of pendingTxns) {
        if (!txRow.reference) continue;
        try {
          const { outcome, verifyData } =
            await resolveTopupAgainstFlutterwave(txRow);

          if (outcome === "completed") {
            const res = await completeTopupTransaction(txRow, verifyData);
            if (res.status === "completed" || res.status === "partial") {
              reconciledCount++;
            }
          } else if (outcome === "failed" || outcome === "stale") {
            await supabase
              .from("wallet_transactions")
              .update({ status: "failed" })
              .eq("id", txRow.id)
              .eq("status", "pending");
            notifyUser(txRow.user_id, { type: "topup_failed", title: "Top-up failed", body: "Your top-up could not be completed. Please try again or contact support.", data: { url: "/wallet" } }).catch(() => {});
            reconciledCount++;
          }
          // outcome === "pending": still within the staleness window with
          // no definitive answer from Flutterwave — leave it alone, we'll
          // check again next sweep.
        } catch (itemErr) {
          // Only unexpected errors from our own DB writes land here now —
          // resolveTopupAgainstFlutterwave() already swallows and reports
          // Flutterwave-side failures internally, so this being reached
          // doesn't mean the row gets stuck: it'll be retried next sweep.
          console.error(
            `Reconcile: unexpected error for ${txRow.reference}:`,
            itemErr,
          );
          errorCount++;
        }
      }
    }

    // 2. Audit completed topups for any inaccurate platform fee calculations (e.g. N2 instead of N2.15)
    const { data: completedTxns } = await supabase
      .from("wallet_transactions")
      .select("*")
      .eq("type", "topup")
      .eq("status", "completed");

    if (completedTxns && completedTxns.length > 0) {
      for (const txRow of completedTxns) {
        const grossAmount = Number(txRow.gross_amount || txRow.amount || 0);
        if (grossAmount <= 0) continue;

        const corrected = calculatePaymentProcessingFee(
          grossAmount,
          grossAmount * 0.02,
        );

        const currentFee = Number(txRow.platform_fee || 0);
        const currentNet = Number(txRow.net_amount || 0);

        if (
          currentFee !== corrected.totalPlatformFee ||
          currentNet !== corrected.netAmount
        ) {
          await supabase
            .from("wallet_transactions")
            .update({
              gross_amount: corrected.grossAmount,
              processing_fee: corrected.processingFee,
              vat_fee: corrected.vatOnProcessingFee,
              platform_fee: corrected.totalPlatformFee,
              net_amount: corrected.netAmount,
              fee_rate: corrected.feeRate,
              fee_is_estimated: corrected.feeIsEstimated,
            })
            .eq("id", txRow.id);
          reconciledCount++;
        }
      }
    }

    if (reconciledCount > 0) {
      console.log(`Topup reconciliation: auto-reconciled ${reconciledCount} pending topups.`);
    }
    return { reconciled: reconciledCount, errors: errorCount, total: pendingTxns.length };
  } catch (err) {
    console.error("Topup background reconciliation error:", err.message);
    return { reconciled: 0, errors: 1 };
  }
}

// Reconciliation now runs on-demand — see reconcilePendingTopups() above
// for why setInterval/setTimeout were removed (serverless has no
// persistent process for them to run in). It's triggered by:
//   1. GET /api/admin/topups/reconcile-status (below) — auto-fired,
//      throttled, whenever the admin dashboard loads
//   2. POST /api/admin/topups/reconcile (below) — manual admin button,
//      force: true, bypasses the throttle
//   3. POST /api/wallet/topup/verify — re-checks that specific user's
//      row every time they view their wallet page
// Point an external scheduler (Vercel Cron / Supabase pg_cron / etc.)
// at #2 on a fixed schedule to catch transactions nobody ever revisits.

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

    if (txRow.status === "partial") {
      return res.json({
        status: "partial",
        amount_expected: txRow.gross_amount ?? txRow.amount,
        amount_received: txRow.amount_received,
      });
    }

    const { outcome, verifyData } = await resolveTopupAgainstFlutterwave(txRow);

    if (outcome === "completed") {
      const result = await completeTopupTransaction(txRow, verifyData);

      if (result.error) {
        return res
          .status(500)
          .json({ error: "Failed to update transaction status" });
      }

      // completeTopupTransaction() itself may decide this is actually an
      // underpayment (see the amount guard inside it) even though
      // Flutterwave reported "successful" — don't report "completed" to
      // the client in that case, or the UI shows success on a wallet that
      // was never credited.
      if (result.status === "partial") {
        return res.json({
          status: "partial",
          amount_expected: result.expectedAmount,
          amount_received: result.confirmedAmount,
        });
      }

      if (result.status === "currency_mismatch") {
        return res.json({
          status: "pending",
          message: "Under manual review",
        });
      }

      return res.json({
        status: "completed",
        already_completed: !!result.already_completed,
      });
    }

    if (outcome === "failed" || outcome === "stale") {
      await supabase
        .from("wallet_transactions")
        .update({ status: "failed" })
        .eq("id", txRow.id)
        .eq("status", "pending");

      notifyUser(txRow.user_id, { type: "topup_failed", title: "Top-up failed", body: "Your top-up could not be completed. Please try again or contact support.", data: { url: "/wallet" } }).catch(() => {});

      return res.json({ status: "failed" });
    }

    // outcome === "pending": still within the staleness window with no
    // definitive answer from Flutterwave yet.
    return res.json({ status: "pending" });
  } catch (err) {
    console.error("Topup verify error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/admin/topups/reconcile — Admin manual reconciliation ("Sync &
// Reconcile Statuses" button). Always forces a real sweep, ignoring the
// throttle, since the admin explicitly asked for a fresh check.
app.post(
  "/api/admin/topups/reconcile",
  authenticateRequest,
  requireAdmin,
  async (_req, res) => {
    try {
      const stats = await reconcilePendingTopups({ force: true });
      return res.json({ ok: true, stats });
    } catch (err) {
      console.error("Admin topup reconcile error:", err);
      return res.status(500).json({ error: "Failed to reconcile top-ups" });
    }
  },
);

// GET /api/admin/topups/reconcile-status — fired automatically by the admin
// dashboard on every load (not just the manual button), so stale pending
// rows get cleared up just by an admin looking at the page. Throttled to
// once a minute internally, so it's cheap to call on every page view.
app.get(
  "/api/admin/topups/reconcile-status",
  authenticateRequest,
  requireAdmin,
  async (_req, res) => {
    try {
      const stats = await reconcilePendingTopups();
      return res.json({ ok: true, stats });
    } catch (err) {
      console.error("Admin topup auto-reconcile error:", err);
      // Non-critical — the dashboard just shows whatever's already in the DB
      return res.json({ ok: false });
    }
  },
);

// ─── Nigerian Banks Data & Flutterwave Integration ────────────────────────────
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

    if (!FLUTTERWAVE_SECRET_KEY) {
      console.error(
        "Cannot fetch banks: FLUTTERWAVE_SECRET_KEY not configured",
      );
      return res
        .status(503)
        .json({ error: "Payment gateway not configured — cannot load banks" });
    }

    try {
      const response = await flutterwaveAxios.get("/banks/NG");

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

      console.warn("Flutterwave banks response invalid:", response.data);
    } catch (flwErr) {
      console.warn(
        "Flutterwave fetch banks error — no valid cached data available:",
        flwErr.message,
      );
    }

    if (cachedBanksList) {
      console.warn(
        "Falling back to stale cached banks list (cache expired but live fetch failed)",
      );
      return res.json({
        status: "success",
        data: cachedBanksList,
        source: "cache-stale",
      });
    }

    return res.status(502).json({
      error:
        "Could not load banks from payment gateway. Please try again later.",
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

    if (!FLUTTERWAVE_SECRET_KEY) {
      console.error(
        "Bank resolve rejected: FLUTTERWAVE_SECRET_KEY not configured",
      );
      return res
        .status(503)
        .json({
          error: "Payment gateway not configured — cannot verify account",
        });
    }

    try {
      const response = await flutterwaveAxios.post("/accounts/resolve", {
        account_number: accountNumber,
        account_bank: bankCode,
      });

      if (
        response.data &&
        (response.data.status === "success" || response.data.data?.account_name)
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

      console.warn(
        "Flutterwave resolve returned no account_name:",
        response.data,
      );
      return res.status(400).json({
        error:
          "Could not verify account — please check account number and bank selected.",
      });
    } catch (flwErr) {
      console.warn(
        "Flutterwave resolve error:",
        flwErr.response?.data || flwErr.message,
      );
      const rawMsg = flwErr.response?.data?.message || "";
      const errMsg =
        rawMsg.includes("destbankcode") || rawMsg.includes("account_bank")
          ? "This bank is not currently supported for account verification. Please try a different bank or contact support."
          : rawMsg ||
            "Could not verify account — please check account number and bank selected.";
      return res.status(400).json({ error: errMsg });
    }
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

    // Retake path — the user has already paid, so just create a new
    // (free) attempt row. Shared by two callers: the normal "already
    // paid" branch below, AND the race-fallback below it, for when a
    // concurrent request for the same user+quiz wins the charge and
    // this one loses — see the unique-violation handling further down.
    const createFreeAttempt = async () => {
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
    };

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

      const { error: payErr } = await supabase.from("wallet_transactions").insert({
        id: paymentTxnId,
        user_id: req.user.id,
        amount: -priceNaira,
        type: "quiz_payment",
        status: "completed",
        reference: payRef,
        related_quiz_id: quiz.id,
        related_attempt_id: attemptId,
      });

      if (payErr) {
        // 23505 = unique_violation on the partial unique index added in
        // migration 037 (user_id, related_quiz_id) where type =
        // 'quiz_payment' and status = 'completed'. This means a
        // concurrent request for the same user+quiz — e.g. a fast
        // double-tap, or a client retry firing before the first
        // request's response came back — already recorded the
        // completed payment in between our check above and this insert.
        // The user has genuinely already paid: give them the same free
        // attempt a normal retake would get, don't charge them again,
        // and don't surface this as an error.
        if (payErr.code === "23505") {
          return createFreeAttempt();
        }
        console.error("Wallet transaction insert error:", payErr);
        return res.status(500).json({ error: "Failed to record payment" });
      }

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
      return createFreeAttempt();
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
    const { data: profileRow } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", req.user.id)
      .maybeSingle();
    const isAdmin = profileRow?.role === "admin";
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
  "/api/creator/courses/upsert",
  authenticateRequest,
  async (req, res) => {
    try {
      const {
        code,
        name,
        subject_area,
        level,
        is_computational,
        university_id,
      } = req.body || {};

      // ── Validate required fields ──────────────────────────────────────────
      if (
        !code ||
        typeof code !== "string" ||
        !code.trim() ||
        !name ||
        typeof name !== "string" ||
        !name.trim() ||
        !university_id ||
        typeof university_id !== "string"
      ) {
        return res
          .status(400)
          .json({ error: "code, name, and university_id are required." });
      }

      const courseCode = code.trim().toUpperCase();
      const courseName = name.trim();
      const levelNum =
        typeof level === "number" && Number.isFinite(level) ? level : null;

      // ── Check for existing course (same code + university) ────────────────
      const { data: existing, error: findErr } = await supabase
        .from("courses")
        .select("id")
        .eq("code", courseCode)
        .eq("university_id", university_id)
        .maybeSingle();

      if (findErr) {
        console.error("Course upsert lookup error:", findErr);
        return res.status(500).json({ error: "Failed to look up course." });
      }

      if (existing) {
        // Update metadata on the existing row
        const { data: updated, error: updateErr } = await supabase
          .from("courses")
          .update({
            name: courseName,
            subject_area: subject_area ?? null,
            level: levelNum,
          })
          .eq("id", existing.id)
          .select("id")
          .single();

        if (updateErr) {
          console.error("Course upsert update error:", updateErr);
          return res.status(500).json({ error: "Failed to update course." });
        }
        return res.json({ course_id: updated.id, created: false });
      }

      // ── Insert new course ─────────────────────────────────────────────────
      const { data: inserted, error: insertErr } = await supabase
        .from("courses")
        .insert({
          name: courseName,
          code: courseCode,
          subject_area: subject_area ?? null,
          level: levelNum,
          is_computational: is_computational ?? false,
          university_id,
        })
        .select("id")
        .single();

      if (insertErr || !inserted) {
        console.error("Course upsert insert error:", insertErr);
        return res.status(500).json({ error: "Failed to create course." });
      }
      return res.status(201).json({ course_id: inserted.id, created: true });
    } catch (err) {
      console.error("Course upsert outer error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

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

      notifyUser(req.user.id, {
        type: "payout_requested",
        title: "Payout request received",
        body: `We've received your payout request of ₦${Number(inserted.amount).toLocaleString()}. We'll review it shortly.`,
        data: { url: "/creator/payouts" },
      }).catch(() => {});

      try {
        const { data: adminRows } = await supabase
          .from("profiles")
          .select("id")
          .eq("role", "admin");
        if (adminRows && adminRows.length > 0) {
          const creatorName = profile.full_name || "A creator";
          for (const admin of adminRows) {
            insertNotification({
              userId: admin.id,
              type: "payout_requested_pending_review",
              title: "New payout request",
              body: `${creatorName} requested a payout of ₦${Number(inserted.amount).toLocaleString()}.`,
              data: { url: "/admin/payouts" },
              createdBy: req.user.id,
            }).catch(() => {});
            sendPushToUser(admin.id, {
              title: "New payout request",
              body: `${creatorName} requested a payout of ₦${Number(inserted.amount).toLocaleString()}.`,
              data: { url: "/admin/payouts" },
            }).catch(() => {});
          }
        }
      } catch (_e) {}

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
          error: "This payout has already been processed or is being processed",
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
        note: "DEMO MODE: transfer not actually sent. Set PAYOUT_MODE=live and provide FLUTTERWAVE_SECRET_KEY for real payouts.",
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
      const transferResp = await flutterwaveTransferAxios.post("/transfers", {
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

      const { data: rejected, error: rejectErr } = await supabase
        .from("payout_requests")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          notes: notes || null,
        })
        .eq("id", payoutRequestId)
        .in("status", ["pending", "failed", "reversed"])
        .select()
        .single();

      if (rejectErr || !rejected) {
        const { data: existingRow } = await supabase
          .from("payout_requests")
          .select("status")
          .eq("id", payoutRequestId)
          .maybeSingle();

        if (!existingRow) {
          return res.status(404).json({ error: "Payout request not found" });
        }

        if (existingRow.status === "rejected") {
          return res.json({ ok: true, already_rejected: true });
        }

        return res.status(409).json({
          error: `Cannot reject a payout with status '${existingRow.status}'. Rejection is only allowed from pending, failed, or reversed states.`,
        });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("Payout reject error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

app.post(
  "/api/admin/payout-requests/:id/mark-paid-manually",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const { id: payoutRequestId } = req.params;
      const { reference } = req.body || {};

      if (!reference || typeof reference !== "string" || !reference.trim()) {
        return res.status(400).json({
          error:
            "Reference / proof of transfer is required — provide the bank transaction reference or other proof of manual payment.",
        });
      }
      const rawReference = reference.trim();

      // ── Atomic conditional lock: only eligible source states ──────────
      const { data: locked, error: lockErr } = await supabase
        .from("payout_requests")
        .update({ status: "processing" })
        .eq("id", payoutRequestId)
        .in("status", ["pending", "failed", "reversed"])
        .select()
        .single();

      if (lockErr || !locked) {
        const { data: existingRow } = await supabase
          .from("payout_requests")
          .select("status")
          .eq("id", payoutRequestId)
          .maybeSingle();

        if (!existingRow) {
          return res.status(404).json({ error: "Payout request not found" });
        }

        if (existingRow.status === "paid") {
          return res.json({
            ok: true,
            already_paid: true,
            note: "This payout is already marked as paid.",
          });
        }

        return res.status(409).json({
          error: `Cannot mark as paid manually a payout with status '${existingRow.status}'. Manual confirmation is only allowed from pending, failed, or reversed states.`,
        });
      }

      const payoutRequestIdFinal = locked.id;
      const creatorId = locked.creator_id;
      const payoutAmount = Number(locked.amount);
      const walletTxnReference = `manual_${payoutRequestIdFinal}`;

      try {
        const { data: creator, error: creatorErr } = await supabase
          .from("profiles")
          .select("*")
          .eq("id", creatorId)
          .single();

        if (creatorErr || !creator) {
          await supabase
            .from("payout_requests")
            .update({
              status: "failed",
              failure_reason: "Creator profile not found during manual pay",
            })
            .eq("id", payoutRequestIdFinal);
          return res.status(404).json({ error: "Creator profile not found" });
        }

        // ── Idempotent wallet_transactions insert ─────────────────────
        const { error: existingTxnErr, data: existingTxn } = await supabase
          .from("wallet_transactions")
          .select("id")
          .eq("reference", walletTxnReference)
          .eq("type", "payout")
          .maybeSingle();

        if (existingTxnErr) {
          throw existingTxnErr;
        }

        if (!existingTxn) {
          const { error: txnInsertErr } = await supabase
            .from("wallet_transactions")
            .insert({
              id: "wtx_" + crypto.randomUUID(),
              user_id: creatorId,
              amount: -payoutAmount,
              type: "payout",
              status: "completed",
              reference: walletTxnReference,
            });
          if (txnInsertErr) throw txnInsertErr;
        }

        // ── Finalize payout_requests row ──────────────────────────────
        const now = new Date().toISOString();
        const { error: finalizeErr } = await supabase
          .from("payout_requests")
          .update({
            status: "paid",
            processed_at: now,
            payment_method: "manual",
            manual_reference: rawReference,
            marked_paid_by: req.user.id,
          })
          .eq("id", payoutRequestIdFinal);
        if (finalizeErr) throw finalizeErr;

        return res.json({
          ok: true,
          status: "paid",
          payout_request_id: payoutRequestIdFinal,
          payment_method: "manual",
          manual_reference: rawReference,
          marked_paid_by: req.user.id,
          wallet_reference: walletTxnReference,
        });
      } catch (innerErr) {
        console.error("Manual payout finalize error:", innerErr);
        try {
          await supabase
            .from("payout_requests")
            .update({
              status: "failed",
              failure_reason:
                innerErr instanceof Error
                  ? innerErr.message
                  : "Unexpected error during manual payout finalization",
            })
            .eq("id", payoutRequestIdFinal);
        } catch (_rollbackErr) {
          // swallow
        }
        return res.status(500).json({ error: "Internal server error" });
      }
    } catch (err) {
      console.error("Manual payout outer error:", err);
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
        .maybeSingle();

      if (appErr || !application) {
        return res.status(404).json({ error: "Creator application not found" });
      }

      if (application.status === "approved") {
        return res.json({ ok: true, already_approved: true });
      }
      if (application.status === "rejected") {
        return res.status(409).json({
          error: "Cannot approve an application that has already been rejected",
        });
      }

      const { error: updateErr } = await supabase
        .from("creator_applications")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
        })
        .eq("id", applicationId)
        .eq("status", "pending");

      if (updateErr) {
        const { data: recheck } = await supabase
          .from("creator_applications")
          .select("status")
          .eq("id", applicationId)
          .maybeSingle();
        if (recheck?.status === "approved") {
          return res.json({ ok: true, already_approved: true });
        }
        return res.status(409).json({
          error: `Creator application has status '${recheck?.status}' and cannot be approved`,
        });
      }

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

      const { data: application, error: appErr } = await supabase
        .from("creator_applications")
        .select("status")
        .eq("id", applicationId)
        .maybeSingle();

      if (appErr || !application) {
        return res.status(404).json({ error: "Creator application not found" });
      }

      if (application.status === "rejected") {
        return res.json({ ok: true, already_rejected: true });
      }
      if (application.status === "approved") {
        return res.status(409).json({
          error: "Cannot reject an application that has already been approved",
        });
      }

      const { error: updateErr } = await supabase
        .from("creator_applications")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          notes: notes || null,
        })
        .eq("id", applicationId)
        .eq("status", "pending");

      if (updateErr) {
        const { data: recheck } = await supabase
          .from("creator_applications")
          .select("status")
          .eq("id", applicationId)
          .maybeSingle();
        if (recheck?.status === "rejected") {
          return res.json({ ok: true, already_rejected: true });
        }
        return res.status(409).json({
          error: `Creator application has status '${recheck?.status}' and cannot be rejected`,
        });
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("Creator reject error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

// ─── Admin Management Endpoints ─────────────────────────────────────────────

// GET /api/admin/users — paginated profiles + auth emails
app.get(
  "/api/admin/users",
  authenticateRequest,
  requireAdmin,
  async (req, res) => {
    try {
      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const pageSize = Math.min(
        100,
        Math.max(1, Number.parseInt(req.query.pageSize, 10) || 25),
      );
      const role = String(req.query.role || "all");
      const universityId = String(req.query.universityId || "all");
      const search = String(req.query.search || "").trim();

      let profilesQuery = supabase
        .from("profiles")
        .select("*", { count: "exact" })
        .order("created_at", { ascending: false });

      if (role === "users") profilesQuery = profilesQuery.eq("role", "user").eq("is_suspended", false);
      else if (role === "creators") profilesQuery = profilesQuery.eq("role", "creator");
      else if (role === "admins") profilesQuery = profilesQuery.eq("role", "admin");
      else if (role === "suspended") profilesQuery = profilesQuery.eq("is_suspended", true);
      if (universityId !== "all") profilesQuery = profilesQuery.eq("university_id", universityId);
      if (search) profilesQuery = profilesQuery.ilike("full_name", `%${search.replace(/[%,]/g, "")}%`);

      const start = (page - 1) * pageSize;
      const { data: profiles, count, error: profErr } = await profilesQuery.range(
        start,
        start + pageSize - 1,
      );
      if (profErr)
        return res.status(500).json({ error: "Failed to fetch profiles" });

      // Resolve emails only for the page being returned; never load the full
      // auth directory just to render one admin page.
      const authUsers = await Promise.all(
        (profiles || []).map(async (profile) => {
          const { data } = await supabase.auth.admin.getUserById(profile.id);
          return [profile.id, data?.user?.email || null];
        }),
      );
      const emailMap = Object.fromEntries(authUsers);

      const enriched = (profiles || []).map((p) => ({
        ...p,
        email: emailMap[p.id] || null,
      }));

      return res.json({
        users: enriched,
        total: count || 0,
        page,
        pageSize,
      });
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
      const uniId = "uni_" + crypto.randomUUID();
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

// app.listen is only used in local development.
// On Vercel (serverless), the exported app is used directly as the handler.
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;