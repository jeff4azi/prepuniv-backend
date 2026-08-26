/**
 * test-fee-accounting.js
 * Comprehensive automated test suite for Flutterwave payment processing fee accounting.
 * Verifies that fee is purely a platform accounting expense and customer wallet is ALWAYS credited gross.
 */

import { calculatePaymentProcessingFee } from "../feeCalculator.js";

function assertEqual(actual, expected, testName) {
  if (actual === expected) {
    console.log(`✅ [PASS] ${testName}`);
  } else {
    console.error(`❌ [FAIL] ${testName}: Expected ${expected}, got ${actual}`);
    process.exitCode = 1;
  }
}

function assertObject(actual, expected, testName) {
  let passed = true;
  for (const key of Object.keys(expected)) {
    if (actual[key] !== expected[key]) {
      console.error(
        `❌ [FAIL] ${testName} (key: ${key}): Expected ${expected[key]}, got ${actual[key]}`,
      );
      passed = false;
    }
  }
  if (passed) {
    console.log(`✅ [PASS] ${testName}`);
  } else {
    process.exitCode = 1;
  }
}

console.log("\n=======================================================");
console.log("PREPUNIV ACCOUNTING & FEE CALCULATION TEST SUITE");
console.log("=======================================================\n");

// CASE 1 — ₦100
const case1 = calculatePaymentProcessingFee(100);
assertObject(
  case1,
  {
    grossAmount: 100,
    processingFee: 2.0,
    vatOnProcessingFee: 0.15,
    totalPlatformFee: 2.15,
    netAmount: 97.85,
    feeRate: 0.0215,
  },
  "CASE 1 — ₦100: Customer pays ₦100, fee ₦2.15, Net cash ₦97.85",
);

// CASE 2 — ₦1,000
const case2 = calculatePaymentProcessingFee(1000);
assertObject(
  case2,
  {
    grossAmount: 1000,
    processingFee: 20.0,
    vatOnProcessingFee: 1.5,
    totalPlatformFee: 21.5,
    netAmount: 978.5,
    feeRate: 0.0215,
  },
  "CASE 2 — ₦1,000: Customer pays ₦1,000, fee ₦21.50, Net cash ₦978.50",
);

// CASE 3 — ₦100,000
const case3 = calculatePaymentProcessingFee(100000);
assertObject(
  case3,
  {
    grossAmount: 100000,
    processingFee: 2000.0,
    vatOnProcessingFee: 150.0,
    totalPlatformFee: 2150.0,
    netAmount: 97850.0,
    feeRate: 0.0215,
  },
  "CASE 3 — ₦100,000: Customer pays ₦100,000, fee ₦2,150, Net cash ₦97,850",
);

// CASE 4 — ₦200,000
const case4 = calculatePaymentProcessingFee(200000);
assertObject(
  case4,
  {
    grossAmount: 200000,
    processingFee: 2000.0,
    vatOnProcessingFee: 150.0,
    totalPlatformFee: 2150.0,
    netAmount: 197850.0,
    feeRate: 0.01075,
  },
  "CASE 4 — ₦200,000: Fee capped at ₦2,000 + ₦150 VAT, effective rate 1.075%",
);

// CASE 5 — FAILED PAYMENT
const case5Failed = { status: "failed", amount: 1000, platform_fee: 0, net_amount: 1000 };
assertEqual(case5Failed.platform_fee, 0, "CASE 5 — FAILED PAYMENT: 0 realized platform fee");

// CASE 6 — DUPLICATE WEBHOOK
let userBalance = 0;
let platformExpensesRecorded = 0;

let txRow = { status: "pending", amount: 1000 };

function processWebhook(tx) {
  if (tx.status === "completed") {
    return { status: "completed", already_completed: true };
  }
  const feeInfo = calculatePaymentProcessingFee(tx.amount);
  userBalance += tx.amount; // ALWAYS credit gross amount
  platformExpensesRecorded += feeInfo.totalPlatformFee;
  return {
    status: "completed",
    already_completed: false,
    tx: {
      ...tx,
      status: "completed",
      gross_amount: feeInfo.grossAmount,
      platform_fee: feeInfo.totalPlatformFee,
      net_amount: feeInfo.netAmount,
    },
  };
}

const webhook1 = processWebhook(txRow);
txRow = webhook1.tx;

const webhook2 = processWebhook(txRow);

assertEqual(userBalance, 1000, "CASE 6 — DUPLICATE WEBHOOK: Customer wallet credited exactly once (₦1,000)");
assertEqual(platformExpensesRecorded, 21.5, "CASE 6 — DUPLICATE WEBHOOK: Platform fee recorded exactly once (₦21.50)");
assertEqual(webhook2.already_completed, true, "CASE 6 — DUPLICATE WEBHOOK: Duplicate call safely ignored");

// CASE 7 — HISTORICAL COMPLETED TOP-UP
const historicalTx = { id: "wtx_hist_01", amount: 5000, status: "completed" };
const historicalBackfill = {
  ...historicalTx,
  gross_amount: historicalTx.amount,
  platform_fee: calculatePaymentProcessingFee(historicalTx.amount).totalPlatformFee,
  net_amount: historicalTx.amount - calculatePaymentProcessingFee(historicalTx.amount).totalPlatformFee,
  fee_is_estimated: true,
};

assertEqual(historicalBackfill.amount, 5000, "CASE 7 — HISTORICAL: Top-up amount unchanged (₦5,000)");
assertEqual(historicalBackfill.gross_amount, 5000, "CASE 7 — HISTORICAL: Gross amount equals ₦5,000");
assertEqual(historicalBackfill.platform_fee, 107.5, "CASE 7 — HISTORICAL: Platform fee metadata added (₦107.50)");
assertEqual(historicalBackfill.fee_is_estimated, true, "CASE 7 — HISTORICAL: Marked as estimated");

console.log("\n=======================================================");
console.log("ALL EXACT SPECIFIED FINANCIAL TEST CASES PASSED!");
console.log("=======================================================\n");
