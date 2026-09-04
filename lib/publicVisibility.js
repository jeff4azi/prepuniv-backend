/**
 * publicVisibility.js
 *
 * Single source of truth for "is this content publicly visible?" rules.
 *
 * Both the sitemap route (GET /sitemap.xml) and any future OG-tag middleware
 * that handles /quiz/:id and /profile/creator/:id previews should import from
 * here rather than re-stating these four conditions independently. If a future
 * migration adds a new visibility field (e.g. is_flagged, is_under_review),
 * update these helpers once and both consumers get it automatically.
 *
 * Rules as of the current schema
 * ───────────────────────────────
 * A quiz is publicly visible when:
 *   is_published            = true   (creator hasn't unpublished it)
 *   unpublished_by_admin    = false  (admin hasn't force-unpublished it)
 *
 * A creator profile is publicly visible when:
 *   is_approved_creator     = true   (admin has approved the application)
 *   is_suspended            = false  (account is not suspended)
 */

/**
 * Returns true if a quiz row should appear in public surfaces
 * (sitemap, OG previews, search index).
 *
 * @param {{ is_published: boolean, unpublished_by_admin: boolean }} quiz
 */
export function isQuizPubliclyVisible(quiz) {
  return quiz.is_published === true && quiz.unpublished_by_admin === false;
}

/**
 * Returns true if a creator profile should appear in public surfaces
 * (sitemap, OG previews, search index).
 *
 * @param {{ is_approved_creator: boolean, is_suspended: boolean }} profile
 */
export function isCreatorPubliclyVisible(profile) {
  return profile.is_approved_creator === true && profile.is_suspended === false;
}
