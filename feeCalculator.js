/**
 * feeCalculator.js — Centralized payment processing fee calculation for PrepUniv
 *
 * Business Rules:
 * - Gateway processing fee: 2.00% (0.02)
 * - VAT on gateway fee: 7.5% (0.075) of the processing fee
 * - Combined effective fee rate: 2.15% (0.0215)
 * - Processing fee cap: ₦2,000.00 (before VAT)
 * - VAT on cap: ₦150.00 (7.5% of ₦2,000)
 * - Maximum platform fee: ₦2,150.00
 */

export const FEE_CONFIG = {
  PROCESSING_FEE_RATE: 0.02, // 2.0%
  VAT_RATE: 0.075, // 7.5% on processing fee
  EFFECTIVE_FEE_RATE: 0.0215, // 2.15%
  PROCESSING_FEE_CAP: 2000.0, // ₦2,000 max processing fee
  VAT_ON_CAP: 150.0, // ₦150 VAT on capped fee
  MAX_PLATFORM_FEE: 2150.0, // ₦2,150 max total fee
};

export function roundToTwoDecimals(num) {
  return Math.round((num + Number.EPSILON) * 100) / 100;
}

export function roundToFiveDecimals(num) {
  return Math.round((num + Number.EPSILON) * 100000) / 100000;
}

/**
 * Calculates payment processing fees for top-ups.
 *
 * @param {number} grossAmount - The amount paid by customer in NGN (Naira).
 * @param {number|null} actualGatewayFee - Optional confirmed base gateway fee from Flutterwave (before 7.5% VAT).
 * @param {number|null} amountSettled - Optional confirmed settled amount from Flutterwave.
 * @returns {object} Fee calculation breakdown.
 */
export function calculatePaymentProcessingFee(
  grossAmount,
  actualGatewayFee = null,
  amountSettled = null,
) {
  const numericGross = Math.max(0, Number(grossAmount) || 0);

  if (numericGross <= 0) {
    return {
      grossAmount: 0,
      processingFee: 0,
      vatOnProcessingFee: 0,
      totalPlatformFee: 0,
      netAmount: 0,
      feeRate: FEE_CONFIG.EFFECTIVE_FEE_RATE,
      feeIsEstimated: false,
    };
  }

  // 1. If gateway reported an explicit settled amount (e.g. 97.85 NGN)
  if (
    amountSettled !== null &&
    amountSettled !== undefined &&
    !isNaN(Number(amountSettled)) &&
    Number(amountSettled) > 0
  ) {
    const numericSettled = Number(amountSettled);
    const totalPlatformFee = roundToTwoDecimals(numericGross - numericSettled);
    const processingFee = roundToTwoDecimals(
      totalPlatformFee / (1 + FEE_CONFIG.VAT_RATE),
    );
    const vatOnProcessingFee = roundToTwoDecimals(
      totalPlatformFee - processingFee,
    );
    const feeRate = roundToFiveDecimals(totalPlatformFee / numericGross);

    return {
      grossAmount: numericGross,
      processingFee,
      vatOnProcessingFee,
      totalPlatformFee,
      netAmount: roundToTwoDecimals(numericSettled),
      feeRate,
      feeIsEstimated: false,
    };
  }

  // 2. If gateway reported explicit base fee (e.g. 2.00 NGN)
  if (
    actualGatewayFee !== null &&
    actualGatewayFee !== undefined &&
    !isNaN(Number(actualGatewayFee))
  ) {
    const baseFee = Math.max(0, Number(actualGatewayFee));
    const processingFee = roundToTwoDecimals(baseFee);
    const vatOnProcessingFee = roundToTwoDecimals(
      processingFee * FEE_CONFIG.VAT_RATE,
    );
    const totalPlatformFee = roundToTwoDecimals(
      processingFee + vatOnProcessingFee,
    );
    const netAmount = roundToTwoDecimals(numericGross - totalPlatformFee);
    const feeRate = roundToFiveDecimals(totalPlatformFee / numericGross);

    return {
      grossAmount: numericGross,
      processingFee,
      vatOnProcessingFee,
      totalPlatformFee,
      netAmount,
      feeRate,
      feeIsEstimated: false,
    };
  }

  // 3. Formula-based fee calculation (2.0% processing fee + 7.5% VAT = 2.15% effective rate)
  const uncappedProcessingFee = numericGross * FEE_CONFIG.PROCESSING_FEE_RATE;
  const processingFee = roundToTwoDecimals(
    Math.min(uncappedProcessingFee, FEE_CONFIG.PROCESSING_FEE_CAP),
  );
  const vatOnProcessingFee = roundToTwoDecimals(
    processingFee * FEE_CONFIG.VAT_RATE,
  );
  const totalPlatformFee = roundToTwoDecimals(
    processingFee + vatOnProcessingFee,
  );
  const netAmount = roundToTwoDecimals(numericGross - totalPlatformFee);
  const feeRate =
    numericGross > 0
      ? roundToFiveDecimals(totalPlatformFee / numericGross)
      : 0;

  return {
    grossAmount: numericGross,
    processingFee,
    vatOnProcessingFee,
    totalPlatformFee,
    netAmount,
    feeRate,
    feeIsEstimated: false,
  };
}
