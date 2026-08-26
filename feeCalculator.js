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
 * @param {number|null} actualGatewayFee - Optional confirmed gateway fee from Flutterwave response.
 * @returns {object} Fee calculation breakdown.
 */
export function calculatePaymentProcessingFee(
  grossAmount,
  actualGatewayFee = null,
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

  // If gateway reported an explicit total fee, use it
  if (
    actualGatewayFee !== null &&
    actualGatewayFee !== undefined &&
    !isNaN(Number(actualGatewayFee))
  ) {
    const totalPlatformFee = roundToTwoDecimals(
      Math.max(0, Number(actualGatewayFee)),
    );
    const processingFee = roundToTwoDecimals(
      totalPlatformFee / (1 + FEE_CONFIG.VAT_RATE),
    );
    const vatOnProcessingFee = roundToTwoDecimals(
      totalPlatformFee - processingFee,
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

  // Formula-based fee calculation
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
