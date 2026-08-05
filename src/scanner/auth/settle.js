/**
 * Wait for SPA navigations / redirects to finish before DOM or storage access.
 */
async function settlePage(page, { networkIdleMs = 6000, pauseMs = 500 } = {}) {
  try {
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 });
  } catch {
    /* ignore */
  }
  try {
    await page.waitForLoadState('networkidle', { timeout: networkIdleMs });
  } catch {
    /* many SPAs never reach networkidle */
  }
  if (pauseMs > 0) {
    await page.waitForTimeout(pauseMs);
  }
}

async function safeEvaluate(page, fn, arg, { retries = 3 } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      await settlePage(page, { pauseMs: i === 0 ? 300 : 500 });
      return arg === undefined ? await page.evaluate(fn) : await page.evaluate(fn, arg);
    } catch (err) {
      lastErr = err;
      const msg = String(err?.message || err);
      if (!/Execution context was destroyed|navigation|Target closed|frame was detached/i.test(msg)) {
        throw err;
      }
      await page.waitForTimeout(350 * (i + 1));
    }
  }
  throw lastErr;
}

module.exports = { settlePage, safeEvaluate };
