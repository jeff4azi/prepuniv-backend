/**
 * ogMiddleware.js — Server-side Open Graph / meta tag injection
 *
 * Intercepts GET requests for /quiz/:id and /profile/creator/:id before the
 * SPA fallback so social-platform crawlers (WhatsApp, Twitter/X, Discord,
 * Telegram, iMessage, etc.) receive HTML with page-specific <meta> tags.
 * Real browsers receive the same HTML and then hydrate the React SPA
 * normally — this middleware only pre-populates the tags, it never redirects.
 *
 * ⚠️  DEPLOYMENT NOTE — READ BEFORE DEPLOYING  ⚠️
 * ──────────────────────────────────────────────────────────────────────────
 * The PrepUniv frontend (prepuniv/) is deployed as a SEPARATE Vercel project
 * from this backend (prepuniv-backend/). The frontend's vercel.json rewrites
 * ALL requests to /index.html — they are served by Vercel's CDN and NEVER
 * reach this Express app.
 *
 * That means THIS MIDDLEWARE CANNOT INTERCEPT /quiz/:id OR /profile/creator/:id
 * requests from the frontend's domain in production. Social crawlers hit the
 * frontend's origin (e.g. https://www.prepuniv.com/quiz/abc), which Vercel
 * CDN answers with the generic /index.html before the request ever reaches
 * this server.
 *
 * To make OG tags work in production, ONE of the following must happen:
 *
 *   Option A (recommended): Deploy frontend and backend on the SAME Vercel
 *   project or domain, so /quiz/:id and /profile/creator/:id requests can be
 *   routed to this Express app first. Restructure vercel.json so
 *   /(quiz|profile)/... routes go to /api/index (this server) and everything
 *   else falls through to /index.html (the SPA).
 *
 *   Option B: Use Vercel Edge Middleware (middleware.ts in the frontend repo)
 *   to detect crawler User-Agents on /quiz/:id and /profile/creator/:id,
 *   fetch data from Supabase at the edge, and rewrite the HTML response —
 *   no changes to the backend needed.
 *
 *   Option C: Use a CDN/reverse proxy (Cloudflare Workers, etc.) in front of
 *   the frontend to intercept crawler requests and inject OG tags.
 *
 * This file is fully functional for local development (where the Express
 * server serves a proxied or co-located SPA) and for any deployment
 * architecture where the same Express app serves the static SPA files.
 * In the current split deployment it will NOT affect production link previews
 * without one of the above infrastructure changes.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Caching: generated HTML is cached in-memory with a 5-minute TTL to avoid
 * hammering Supabase on every crawler hit (social crawlers often send several
 * requests per shared link). This matches the banks-list caching pattern
 * already used in index.js.
 *
 * Error handling: any DB lookup failure, missing quiz/profile, or unexpected
 * error causes the middleware to fall through and serve the unmodified default
 * index.html — the page still loads for real visitors, just without a rich
 * preview.
 */

import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import {
  isQuizPubliclyVisible,
  isCreatorPubliclyVisible,
} from "./lib/publicVisibility.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── In-memory cache (mirrors banks-list pattern in index.js) ─────────────────
const OG_CACHE = new Map(); // key → { html: string, expiresAt: number }
const OG_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getCached(key) {
  const entry = OG_CACHE.get(key);
  if (entry && Date.now() < entry.expiresAt) return entry.html;
  OG_CACHE.delete(key);
  return null;
}

function setCache(key, html) {
  OG_CACHE.set(key, { html, expiresAt: Date.now() + OG_CACHE_TTL });
}

// ─── Site constants (must match index.html defaults) ──────────────────────────
const SITE_NAME = "PrepUniv";
const SITE_ORIGIN = "https://www.prepuniv.com";
const SITE_DEFAULT_IMAGE = `${SITE_ORIGIN}/PrepUniv.png`;
const SITE_DEFAULT_TITLE = "PrepUniv — CBT & Exam Prep for Nigerian Students";
const SITE_DEFAULT_DESCRIPTION =
  "PrepUniv helps Nigerian university students ace CBT exams with course-specific practice quizzes, created and shared by fellow students and creators.";
const TWITTER_HANDLE = "@PrepUnivijnv";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Truncate a string to maxLen chars, appending ellipsis if truncated. */
function truncate(str, maxLen) {
  if (!str) return "";
  const s = String(str).trim();
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 1).trimEnd() + "…";
}

/**
 * Replace or insert a <meta> tag in the HTML string.
 * Handles both property="…" (OG) and name="…" (Twitter/description) variants.
 */
function setMeta(html, attrName, attrValue, content) {
  // Match existing tag (self-closing or not, single/double quotes)
  const re = new RegExp(
    `<meta\\s[^>]*(?:${attrName}|${attrName.replace(":", "\\:")})\\s*=\\s*["']${escapeRegex(attrValue)}["'][^>]*/?>`,
    "i",
  );
  const tag =
    attrName === "property"
      ? `<meta property="${attrValue}" content="${escapeAttr(content)}" />`
      : `<meta name="${attrValue}" content="${escapeAttr(content)}" />`;

  if (re.test(html)) {
    return html.replace(re, tag);
  }
  // Insert before </head> if tag wasn't found
  return html.replace("</head>", `  ${tag}\n</head>`);
}

/** Replace the <title> tag content. */
function setTitle(html, title) {
  const safe = escapeHtml(title);
  if (/<title>[^<]*<\/title>/i.test(html)) {
    return html.replace(/<title>[^<]*<\/title>/i, `<title>${safe}</title>`);
  }
  return html.replace("</head>", `  <title>${safe}</title>\n</head>`);
}

function escapeAttr(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Read the built SPA index.html from disk.
 * In a co-located deployment the dist/ folder sits next to index.js.
 * Adjust the path if your deployment puts the built SPA elsewhere.
 */
async function readIndexHtml() {
  // Try dist/index.html (Vite build output co-located with the backend)
  const distPath = path.join(__dirname, "dist", "index.html");
  try {
    return await readFile(distPath, "utf-8");
  } catch {
    // Fall back: maybe the repo root has index.html during dev
    const rootPath = path.join(__dirname, "index.html");
    try {
      return await readFile(rootPath, "utf-8");
    } catch {
      return null;
    }
  }
}

/**
 * Inject page-specific OG/meta tags into the base HTML string.
 * @param {string} baseHtml  - The raw index.html content
 * @param {object} meta      - { title, description, url, image, imageAlt }
 * @returns {string} Modified HTML
 */
function injectMeta(baseHtml, { title, description, url, image, imageAlt }) {
  let html = baseHtml;

  // <title>
  html = setTitle(html, title);

  // <meta name="description">
  html = setMeta(html, "name", "description", description);

  // Open Graph
  html = setMeta(html, "property", "og:title", title);
  html = setMeta(html, "property", "og:description", description);
  html = setMeta(html, "property", "og:url", url);
  html = setMeta(html, "property", "og:image", image);
  html = setMeta(html, "property", "og:image:alt", imageAlt);
  html = setMeta(html, "property", "og:type", "article");

  // Twitter/X Card
  const card = "summary_large_image";
  html = setMeta(html, "name", "twitter:card", card);
  html = setMeta(html, "name", "twitter:title", title);
  html = setMeta(html, "name", "twitter:description", description);
  html = setMeta(html, "name", "twitter:image", image);
  html = setMeta(html, "name", "twitter:image:alt", imageAlt);
  html = setMeta(html, "name", "twitter:site", TWITTER_HANDLE);

  // Canonical URL
  html = html.replace(
    /<link\s+rel="canonical"\s+href="[^"]*"\s*\/>/i,
    `<link rel="canonical" href="${escapeAttr(url)}" />`,
  );

  return html;
}

// ─── Middleware factory ────────────────────────────────────────────────────────

/**
 * Returns an Express middleware that intercepts /quiz/:id and
 * /profile/creator/:id GET requests and injects OG tags.
 *
 * @param {import('@supabase/supabase-js').SupabaseClient} supabase
 *   The service-role Supabase client from index.js.
 */
export function createOgMiddleware(supabase) {
  // Regex patterns for the two intercepted route shapes
  const QUIZ_RE = /^\/quiz\/([^/]+)$/;
  const CREATOR_RE = /^\/profile\/creator\/([^/]+)$/;

  return async function ogMiddleware(req, res, next) {
    // Only intercept GET requests that look like a quiz or creator profile URL
    if (req.method !== "GET") return next();

    const quizMatch = QUIZ_RE.exec(req.path);
    const creatorMatch = CREATOR_RE.exec(req.path);

    if (!quizMatch && !creatorMatch) return next();

    const id = (quizMatch || creatorMatch)[1];

    // Validate: must look like a UUID or the text IDs used in seeds (no
    // injection risk, but avoid wasting DB calls on obviously invalid ids)
    // UUIDs: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // Text IDs: quiz_001 style — allow alphanumeric + _ -
    if (!/^[\w-]{1,128}$/.test(id)) return next();

    const cacheKey = req.path;
    const cached = getCached(cacheKey);
    if (cached) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-OG-Cache", "HIT");
      return res.send(cached);
    }

    try {
      const baseHtml = await readIndexHtml();
      if (!baseHtml) {
        // Can't find index.html — just continue to normal static serving
        return next();
      }

      let meta = null;

      if (quizMatch) {
        // ── Quiz page ─────────────────────────────────────────────────────
        const { data: quiz } = await supabase
          .from("quizzes")
          .select("id, title, description, creator_id")
          .eq("id", id)
          .eq("is_published", true)
          .eq("unpublished_by_admin", false)
          .maybeSingle();

        if (!quiz) {
          // Bad/deleted link — fall through to default SPA (no 500, no redirect)
          return next();
        }

        // Try to get the creator's avatar for the OG image
        let ogImage = SITE_DEFAULT_IMAGE;
        if (quiz.creator_id) {
          const { data: creator } = await supabase
            .from("profiles")
            .select("avatar_url")
            .eq("id", quiz.creator_id)
            .maybeSingle();
          if (creator?.avatar_url) {
            ogImage = creator.avatar_url;
          }
        }

        const pageTitle = truncate(`${quiz.title} | ${SITE_NAME}`, 70);
        const rawDesc = quiz.description
          ? truncate(quiz.description, 200)
          : `Practice quiz on PrepUniv — created and shared by Nigerian students and creators.`;

        meta = {
          title: pageTitle,
          description: rawDesc,
          url: `${SITE_ORIGIN}/quiz/${quiz.id}`,
          image: ogImage,
          imageAlt: `${quiz.title} — PrepUniv quiz`,
        };
      } else {
        // ── Creator profile page ──────────────────────────────────────────
        const { data: profile } = await supabase
          .from("profiles")
          .select(
            "id, full_name, avatar_url, bio, is_approved_creator, is_suspended",
          )
          .eq("id", id)
          .in("role", ["creator", "admin"])
          .maybeSingle();

        if (!profile || !isCreatorPubliclyVisible(profile)) {
          // Bad/deleted profile, suspended creator, or unapproved application —
          // fall through to default SPA
          return next();
        }

        // Reuse the exact share-text phrasing from CreatorProfilePage:
        // title prop  → `${profile.full_name} on PrepUniv`
        // text prop   → `Check out ${profile.full_name}'s quizzes on PrepUniv`
        const pageTitle = truncate(`${profile.full_name} on ${SITE_NAME}`, 70);
        const rawDesc = profile.bio
          ? truncate(profile.bio, 200)
          : `Check out ${profile.full_name}'s quizzes on PrepUniv`;

        meta = {
          title: pageTitle,
          description: rawDesc,
          url: `${SITE_ORIGIN}/profile/creator/${profile.id}`,
          image: profile.avatar_url || SITE_DEFAULT_IMAGE,
          imageAlt: `${profile.full_name} — PrepUniv creator`,
        };
      }

      if (!meta) return next();

      const html = injectMeta(baseHtml, meta);
      setCache(cacheKey, html);

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-OG-Cache", "MISS");
      return res.send(html);
    } catch (err) {
      // Any failure — DB error, file read error, etc. — falls through
      // silently so the page still loads for real visitors.
      console.error("[ogMiddleware] error for", req.path, ":", err.message);
      return next();
    }
  };
}
