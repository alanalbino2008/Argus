// Large-graph benchmark: open an investigation from the graph view and measure how long until it is
// usable, how much the main thread is blocked, and the frame rate while zooming and panning.
// Needs Playwright with Chromium, and a server on :8811 started with ARGUS_BOOTSTRAP_ADMIN_KEY set
// to KEY below (see make_large_investigations.py). Prints one JSON line per investigation.
const { chromium } = require('playwright');
const ids = process.argv.slice(2);
const KEY = process.env.ARGUS_BENCH_KEY || 'argus_test-admin-key-0123456789abcdefghijklmnopqrstu';

async function measure(browser, id) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript((key) => {
    sessionStorage.setItem('argus_api_key', key);
    window.__long = [];
    new PerformanceObserver((list) => { for (const e of list.getEntries()) window.__long.push({ start: e.startTime, duration: e.duration }); })
      .observe({ type: 'longtask', buffered: true });
  }, KEY);
  await page.goto('http://localhost:8811/');
  await page.waitForTimeout(1500);
  const skip = page.getByRole('button', { name: 'Skip' });
  if (await skip.count()) await skip.first().click();
  await page.evaluate(() => [...document.querySelectorAll('button, a')].find((el) => el.dataset?.view === 'graph' || /^\s*Graph\s*$/.test(el.textContent))?.click());
  await page.waitForTimeout(800);

  const result = await page.evaluate(async (id) => {
    const live = await import('/static/js/live.js');
    const graph = await import('/static/js/graph.js');
    const st = await import('/static/js/state.js');
    window.__long = [];
    const t0 = performance.now();
    live.openInvestigation(id);
    // Ready: the snapshot has arrived, the graph is drawn, and the main thread has been free for 500 ms.
    let received = 0, snapshotAt = null;
    for (;;) {
      await new Promise((r) => setTimeout(r, 50));
      received = st.state.entities.size;
      if (received && snapshotAt === null) snapshotAt = performance.now() - t0;
      const last = window.__long.at(-1);
      const quiet = !last || performance.now() - (last.start + last.duration) > 500;
      if (received > 0 && graph.counts().nodes > 0 && quiet) break;
      if (performance.now() - t0 > 180000) return { timeout: true };
    }
    const ready = performance.now() - t0 - 500;
    const longs = window.__long.filter((e) => e.start >= t0);
    const blocking = longs.reduce((sum, e) => sum + Math.max(0, e.duration - 50), 0);
    const longest = Math.max(0, ...longs.map((e) => e.duration));

    // Interaction: zoom in and out and pan for 3 s, counting animation frames.
    let frames = 0, worstFrame = 0, last = performance.now(), running = true;
    const tick = (now) => { frames++; worstFrame = Math.max(worstFrame, now - last); last = now; if (running) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
    const start = performance.now();
    let step = 0;
    while (performance.now() - start < 3000) {
      graph.zoomBy(step % 2 ? 0.8 : 1.25);
      step++;
      await new Promise((r) => setTimeout(r, 120));
    }
    running = false;
    const seconds = (performance.now() - start) / 1000;
    const c = graph.counts();
    return { received, snapshot_ms: Math.round(snapshotAt), drawn: c.drawn, bundles: c.bundles, ready_ms: Math.round(ready), blocking_ms: Math.round(blocking),
             longest_task_ms: Math.round(longest), fps: Math.round(frames / seconds), worst_frame_ms: Math.round(worstFrame) };
  }, id);
  await page.close();
  return { id, ...result, errors: errors.slice(0, 2) };
}

(async () => {
  const browser = await chromium.launch();
  for (const id of ids) console.log(JSON.stringify(await measure(browser, id)));
  await browser.close();
})();
