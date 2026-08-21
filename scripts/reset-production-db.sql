-- ============================================================
-- PREPUNIV — PRODUCTION RESET SCRIPT (SQL ATOMIC TRANSACTION)
-- ============================================================
-- Goal: Purge all test/seed data and non-admin users.
-- Preserves: Admin accounts (profiles.role = 'admin') and universities table.
-- Deletes: All non-admin user data, quizzes, questions, attempts, transactions, and courses.
-- ============================================================

BEGIN;

-- 1. Create a temporary table holding the IDs of all preserved Admin users
CREATE TEMP TABLE admin_user_ids AS
SELECT id FROM public.profiles WHERE role = 'admin';

-- 2. Create a temporary table holding the IDs of all Non-Admin users to be deleted
CREATE TEMP TABLE target_user_ids AS
SELECT id FROM auth.users
WHERE id NOT IN (SELECT id FROM admin_user_ids);

-- 3. Create a temporary table holding non-admin quiz IDs to be deleted
CREATE TEMP TABLE target_quiz_ids AS
SELECT id FROM public.quizzes
WHERE creator_id IN (SELECT id FROM target_user_ids);

-- ------------------------------------------------------------
-- FK-SAFE DELETION SEQUENCE
-- ------------------------------------------------------------

-- Step 1: Delete attempt answers associated with attempts to be deleted
DELETE FROM public.attempt_answers
WHERE attempt_id IN (
  SELECT id FROM public.quiz_attempts
  WHERE user_id IN (SELECT id FROM target_user_ids)
     OR quiz_id IN (SELECT id FROM target_quiz_ids)
);

-- Step 2: Delete quiz attempts (by non-admin users OR on non-admin quizzes)
DELETE FROM public.quiz_attempts
WHERE user_id IN (SELECT id FROM target_user_ids)
   OR quiz_id IN (SELECT id FROM target_quiz_ids);

-- Step 3: Delete ALL wallet transactions (including platform_revenue rows where user_id IS NULL)
DELETE FROM public.wallet_transactions;

-- Step 4: Delete reports (by non-admin reporters OR on non-admin quizzes)
DELETE FROM public.reports
WHERE reporter_id IN (SELECT id FROM target_user_ids)
   OR quiz_id IN (SELECT id FROM target_quiz_ids);

-- Step 5: Delete payout requests from non-admin creators
DELETE FROM public.payout_requests
WHERE creator_id IN (SELECT id FROM target_user_ids);

-- Step 6: Delete creator applications from non-admin users
DELETE FROM public.creator_applications
WHERE user_id IN (SELECT id FROM target_user_ids);

-- Step 7: Delete user navigation states for non-admin users
DELETE FROM public.user_nav_state
WHERE user_id IN (SELECT id FROM target_user_ids);

-- Step 8: Delete questions belonging to non-admin quizzes
DELETE FROM public.questions
WHERE quiz_id IN (SELECT id FROM target_quiz_ids);

-- Step 9: Delete quizzes created by non-admin creators
DELETE FROM public.quizzes
WHERE creator_id IN (SELECT id FROM target_user_ids);

-- Step 10: Delete all test/seed courses catalog entries (since quizzes referencing them are now deleted)
DELETE FROM public.courses;

-- Step 11: Delete non-admin users from auth.users (cascades automatically to public.profiles)
DELETE FROM auth.users
WHERE id IN (SELECT id FROM target_user_ids);

-- Clean up temporary tables
DROP TABLE IF EXISTS target_quiz_ids;
DROP TABLE IF EXISTS target_user_ids;
DROP TABLE IF EXISTS admin_user_ids;

COMMIT;
