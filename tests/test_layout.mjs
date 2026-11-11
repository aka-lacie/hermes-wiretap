// Real-browser geometry checks (Playwright + Chromium; skipped by test_layout_browser.py when unavailable).
// Mounts the real bundle inside a dashboard-like host shell (h-dvh, overflow-hidden, header + late banner + padded
// content column — the stock dashboard's structure) against a stub SDK whose responses arrive late, then measures:
// every column's last item is reachable, the panes' top does not move while a session loads or switches, and a
// Calls row stays put when it is expanded or collapsed after scrolling.
// Usage: node test_layout.mjs <index.js> <style.css> <dir containing node_modules/playwright> [chromium executable]
import { createRequire } from "module";
import { readFileSync } from "fs";
import path from "path";

const [, , bundle, css, pwFrom, chromePath] = process.argv;
const { chromium } = createRequire(path.join(pwFrom, "package.json"))("playwright");
const fails = [], notes = [];
const check = (ok, msg) => { if (!ok) fails.push(msg); };

const SHELL = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>${readFileSync(css, "utf8")}
html,body{margin:0;background:#10131a;color:#ddd;font:14px sans-serif}
.app{display:flex;flex-direction:column;height:100dvh;max-height:100dvh;min-height:0;overflow:hidden}
.hdr{height:56px;flex:0 0 auto;border-bottom:1px solid #333}
.banner{flex:0 0 auto;background:#223;overflow:hidden}
.main{display:flex;flex-direction:column;flex:1;min-height:0;min-width:0;overflow:hidden}
.col{display:flex;flex-direction:column;flex:1;min-height:0;padding:24px 24px 0}
.wrap{width:100%;padding-bottom:32px}
.bar{height:34px}
@media (max-width:768px){.app{height:auto;max-height:none;overflow:visible}.main,.col{overflow:visible}}
</style></head><body><div class="app"><div class="hdr"></div><div class="banner" id="banner"></div><div class="main"><div class="col"><div class="wrap">
<div class="mt-root" data-host="dashboard"><div class="mt-bar bar">Wiretap</div><div class="mt-mount" id="mount"></div></div></div></div></div></div></body></html>`;

function fixtures() {
  const now = 1.79e9;
  const rows = (sid) => Array.from({ length: 80 }, (_, i) => ({ id: (sid === "b" ? 5000 : 1000) + i, role: i % 2 ? "assistant" : "user", kind: i % 2 ? "assistant" : "user",
    label: i % 2 ? "ASSISTANT" : "USER", active: 1, timestamp: now + i, content: ("message " + i + " ").repeat(i % 7 ? 3 : 30),
    // every fourth assistant row carries a subagent-length call id and a tool chip; some rows a long tool-call id
    wire: i % 2 ? (i % 4 === 3 ? "h:20260101_000000_abcdef" + sid + ":sa-0-0a1b2c3d-deadbeef:0e1f2a3b" : "h:" + sid + ":c3") : null,
    tool_names: i % 4 === 3 ? ["terminal"] : [], tool_call_id: i % 8 === 2 ? "toolu_01AbCdEfGhIjKlMnOpQrStUvWxYz0123" : null }));
  const ctx = (sid) => ({ id: sid, title: "Session " + sid, ctx_window: 200000, last_prompt_tokens: 90000, message_count: 80, compressor_trigger: 160000,
    hygiene_trigger: 120000, hygiene_msg_limit: 400 });
  const items = (sid) => Array.from({ length: 80 }, (_, i) => ({ i, role: i % 2 ? "assistant" : "user", len: 50, head: "item " + i, row_id: (sid === "b" ? 5000 : 1000) + i,
    row_kind: i % 2 ? "assistant" : "user", row_label: i % 2 ? "ASSISTANT" : "USER" }));
  const calls = (sid) => [1, 2, 3].map((n) => ({ id: "h:" + sid + ":c" + n, n, started: now + n, status: 200, model: "m" }));
  const callRows = Array.from({ length: 100 }, (_, i) => ({ id: "call-" + i, source: "hermes", started: now - i * 30, model: "model-" + (i % 3), family: "claude", provider: "p",
    session_id: "a", status: 200, events: [], prompt_tokens: 40000, cached_tokens: i % 4 ? 39000 : 100, output_tokens: 50, total_s: 3, ttfb_s: 1,
    diverge: i % 4 ? null : JSON.stringify({ why: "tool declarations changed", at: 1, role: "tools", prev_len: 500, cur_len: 520, common_items: 1, items: 9,
      change: { v: 2, path: "tools[0].description", offset: 10, line: 1, before: { prefix: "Read a file", change: "", suffix: "" }, after: { prefix: "Read a file", change: " (v2)", suffix: "" } } }) }));
  return { rows, ctx, items, calls, callRows };
}
// every transcript card keeps its header, chips and links inside its own border (long subagent `wire h:…` ids used to
// run past it); a shortened wire link still names the whole call (text + title) and keeps the call suffix on screen
async function cardsContained(p, label) {
  const bad = await p.evaluate(() => [...document.querySelectorAll(".mti-tl .mti-msg")].flatMap((m) => {
    const c = m.getBoundingClientRect(), right = c.right - parseFloat(getComputedStyle(m).borderRightWidth);
    return [...m.querySelectorAll(".mti-h > *, .mti-chips > *, .mti-chips > * > *")].filter((x) => x.getBoundingClientRect().right > right + 0.5)
      .map((x) => m.dataset.i + ":" + x.className + "(+" + Math.round(x.getBoundingClientRect().right - right) + "px)");
  }));
  check(!bad.length, `${label}: transcript chips overflow their card (${bad.slice(0, 4).join(", ")})`);
  const wl = await p.evaluate(() => {
    const l = document.querySelector('.mti-tl .mti-golink.mt-wire[title*="sa-0-"]'), t = l && l.querySelector(".mti-gotail");
    return l ? { text: l.textContent.trim(), title: l.title, tail: !!t && t.getBoundingClientRect().width > 0 } : null;
  });
  check(wl && /^wire h:\S+:sa-0-\S+:0e1f2a3b →$/.test(wl.text) && /h:\S+:0e1f2a3b/.test(wl.title) && wl.tail,
    `${label}: a shortened wire link keeps its full call id and its call suffix (${JSON.stringify(wl)})`);
}

async function page(browser, w, h, touch) {
  const p = await browser.newPage({ viewport: { width: w, height: h }, hasTouch: !!touch, isMobile: !!touch });
  const errors = [];
  p.on("pageerror", (e) => errors.push(e.message));
  await p.setContent(SHELL);
  await p.evaluate((fx) => {
    const F = eval("(" + fx + ")")();
    window.__delay = { session: 250, compiled: 450 };
    window.__HERMES_PLUGIN_SDK__ = {
      React: { createElement() { return null; } }, hooks: { useState() { return [null, () => {}]; }, useEffect() {}, useRef() { return {}; } },
      fetchJSON(url) {
        const u = new URL(url, "http://x"), id = u.searchParams.get("id") || "a", q = u.pathname.replace("/api/plugins/wiretap", "");
        let body, ms = 20;
        if (q === "/inspector/sessions") body = { main: "a", sessions: [{ id: "a", title: "Session a", source: "cli" }, { id: "b", title: "Session b — a deliberately long assignment title that cannot fit the sessions column", source: "cli" }] };
        else if (q === "/inspector/session") { ms = window.__delay.session; body = { rev: "r" + id, session: { id, title: "Session " + id, source: "cli" }, rows: F.rows(id), total: 80, matched_calls: 3, context: F.ctx(id) }; }
        else if (q === "/inspector/compiled") { ms = window.__delay.compiled; body = { rev: "c" + id, call_id: "h:" + id + ":c3", latest_call: "h:" + id + ":c3", correlated_call: "h:" + id + ":c3", calls: F.calls(id), calls_total: 3,
          session: { id }, context: F.ctx(id), system: { key: "instructions", wire_len: 10, stored_len: 10, matches_stored: true }, rows_after: [],
          wire: { which: "down", layer: "wire", meta: { status: 200, started: 1 }, call: {}, keys: [], list_key: "input", response: { text: "done" }, items: F.items(id) } }; }
        else if (q === "/inspector/wire/part") body = { role: "user", content: ("long wire text ").repeat(900) };
        else if (q === "/inspector/wire/readable") body = { segments: [{ path: "input[0].content", len: 9000, runs: [{ t: ("long wire text ").repeat(900), k: "raw", label: "row" }] }], source: ["content"] };
        else if (q === "/inspector/row") body = { row: { id: +id, role: "user", content: ("row text ").repeat(1500) }, class: { label: "USER" } };
        else if (q === "/calls") body = { rows: Array.from({ length: window.__arrivals || 0 }, (_, k) => Object.assign({}, F.callRows[0], { id: "new-" + k, started: 1.79e9 + 100 + k })).reverse().concat(F.callRows),
          offset: 0, has_more: false, total: 100 + (window.__arrivals || 0), rev: "x" + (window.__arrivals || 0), summary: {}, agg: [], keys: [], fail_keys: [],
          families: window.__fams || [{ family: "claude", label: "Claude", n: 100 }], providers: [], last_scan: {}, last_capture: {}, oldest: 1, now: 1.79e9 };
        else if (q === "/sessions") body = { main: { id: "a" }, sessions: [] };
        else body = {};
        return new Promise((r) => setTimeout(() => r(JSON.parse(JSON.stringify(body))), ms + (window.__slow || 0)));
      },
    };
    window.__HERMES_PLUGINS__ = { register() {} };
    window.__WIRETAP_TEST__ = { expose(x) { window.ui = x; } };
  }, fixtures.toString());
  await p.addScriptTag({ content: readFileSync(bundle, "utf8") });
  return { p, errors };
}
// document coordinates: the phone view scrolls the page to the newest row on purpose; that is not layout shift
const bodyTop = (p) => p.evaluate(() => Math.round(document.querySelector(".mti-body").getBoundingClientRect().top + document.scrollingElement.scrollTop));
async function reach(p, sel, label) {
  // scroll the column (or the page, when the column flows in it) to its end: its last item must be fully on screen
  const r = await p.evaluate((sel) => {
    const el = document.querySelector(sel), last = [...el.querySelectorAll(".mti-msg, .mt-pre, .mtj-panel")].pop();
    el.scrollTop = el.scrollHeight;
    const sc = document.scrollingElement; sc.scrollTop = sc.scrollHeight;
    const e = el.getBoundingClientRect(), l = last ? last.getBoundingClientRect() : e;
    return { colBottom: e.bottom, lastBottom: l.bottom, vh: innerHeight, sh: el.scrollHeight, ch: el.clientHeight, st: el.scrollTop };
  }, sel);
  const ok = r.lastBottom <= Math.min(r.colBottom, r.vh) + 1 && r.colBottom <= r.vh + 1;
  check(ok, `${label}: end of ${sel} unreachable (${JSON.stringify(r)})`);
  return r;
}

const browser = await chromium.launch({ headless: true, executablePath: chromePath || undefined, args: ["--no-sandbox", "--disable-gpu", "--no-zygote"] });
try {
  // ── inspector, desktop ──
  for (const [w, h] of [[1440, 900], [1280, 720]]) {
    const { p, errors } = await page(browser, w, h);
    const tops = [];
    await p.evaluate(() => { window.cleanup = window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
    for (let t = 0; t < 14; t++) { tops.push(await bodyTop(p)); await p.waitForTimeout(60); }
    await p.waitForTimeout(500);
    const t0 = await bodyTop(p);
    notes.push(`${w}x${h} initial tops ${[...new Set(tops)].join(",")} → ${t0}`);
    check(tops.every((x) => Math.abs(x - t0) <= 1), `${w}x${h}: panes moved while the first session loaded (${[...new Set(tops)]} → ${t0})`);
    await reach(p, ".mti-tl", `${w}x${h} transcript timeline`);
    await cardsContained(p, `${w}x${h} transcript`);
    await p.click(".mti-tl .mti-msg[data-i='0']"); await p.waitForTimeout(300);
    await reach(p, ".mti-pane", `${w}x${h} detail pane`);
    // a late host banner (dashboard hints/banners) pushes the panes down: they must shrink, not fall off the bottom
    await p.evaluate(() => { document.getElementById("banner").style.height = "90px"; }); await p.waitForTimeout(200);
    await reach(p, ".mti-tl", `${w}x${h} timeline after a late banner`);
    await p.evaluate(() => { document.getElementById("banner").style.height = "0px"; }); await p.waitForTimeout(200);
    // session switch, slow responses: the panes' top must not move while the new session loads
    await p.evaluate(() => { window.__delay = { session: 600, compiled: 900 }; });
    const t1 = await bodyTop(p), sw = [];
    await p.evaluate(() => document.querySelector('.mti-ses[data-id="b"]').click());
    for (let t = 0; t < 20; t++) { sw.push(await bodyTop(p)); await p.waitForTimeout(60); }
    check(sw.every((x) => Math.abs(x - t1) <= 1), `${w}x${h}: panes moved during a session switch (${t1} → ${[...new Set(sw)]})`);
    // Wire mode: switching modes and loading a call must not move the panes either
    await p.click('[data-mode="wire"]'); const wv = [];
    for (let t = 0; t < 18; t++) { wv.push(await bodyTop(p)); await p.waitForTimeout(60); }
    check(wv.every((x) => Math.abs(x - t1) <= 1), `${w}x${h}: panes moved entering Wire (${t1} → ${[...new Set(wv)]})`);
    await reach(p, ".mti-tl", `${w}x${h} wire timeline`);
    await p.setViewportSize({ width: w - 200, height: h - 120 }); await p.waitForTimeout(300);
    await reach(p, ".mti-tl", `${w - 200}x${h - 120} after resize`);
    check(!errors.length, `page errors: ${errors}`);
    await p.close();
  }
  // ── inspector, phone: the timeline flows in the page; its end must be reachable by scrolling the page ──
  {
    const { p } = await page(browser, 420, 860);
    await p.evaluate(() => { window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
    const ptops = [];
    for (let t = 0; t < 12; t++) { ptops.push(await bodyTop(p)); await p.waitForTimeout(60); }
    await p.waitForTimeout(400);
    const pt0 = await bodyTop(p);
    check(ptops.every((x) => Math.abs(x - pt0) <= 2), `phone: timeline moved while the session loaded (${[...new Set(ptops)]} → ${pt0})`);
    const r = await p.evaluate(() => { const sc = document.scrollingElement; sc.scrollTop = sc.scrollHeight;
      const l = [...document.querySelectorAll(".mti-tl .mti-msg")].pop().getBoundingClientRect(); return { b: l.bottom, vh: innerHeight }; });
    check(r.b <= r.vh + 1, `phone: last timeline row below the fold after scrolling to the end (${JSON.stringify(r)})`);
    await cardsContained(p, "phone transcript");
    await p.close();
  }
  // ── tablet: two narrow panes, so a subagent wire link is wider than its transcript card ──
  {
    const { p } = await page(browser, 820, 1180);
    await p.evaluate(() => { window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
    await p.waitForTimeout(700);
    await cardsContained(p, "820x1180 transcript");
    await p.close();
  }
  // ── Calls: expanding / collapsing a row after scrolling keeps it where it was ──
  for (const [w, h, mobile] of [[1440, 900, false], [420, 860, true]]) {
    const { p } = await page(browser, w, h);
    await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });
    await p.waitForTimeout(700);
    const sel = mobile ? ".mtt-call" : ".mtt-calls tbody tr[data-id]";
    const pick = await p.evaluate(({ sel, mobile }) => {
      const sc = mobile ? document.scrollingElement : document.querySelector(".mtt-tall");
      sc.scrollTop = mobile ? 2400 : 900;
      const row = [...document.querySelectorAll(sel)].find((r) => { const b = r.getBoundingClientRect(); return b.top > 200 && b.bottom < innerHeight - 100; });
      if (!row || !row.dataset.id) return null;
      return { id: row.dataset.id, top: row.getBoundingClientRect().top, st: sc.scrollTop };
    }, { sel, mobile });
    if (!pick) { check(false, `${mobile ? "phone" : "desktop"} calls: rows carry no stable data-id to anchor on`); await p.close(); continue; }
    for (const step of ["expand", "collapse"]) {
      await p.evaluate(({ sel, id }) => document.querySelector(`${sel}[data-id="${id}"]`).dispatchEvent(new MouseEvent("click", { bubbles: true })), { sel, id: pick.id });
      await p.waitForTimeout(150);
      const now = await p.evaluate(({ sel, id, mobile }) => {
        const sc = mobile ? document.scrollingElement : document.querySelector(".mtt-tall"), r = document.querySelector(`${sel}[data-id="${id}"]`);
        return { top: r.getBoundingClientRect().top, st: sc.scrollTop, open: !!document.querySelector(".mtt-det") };
      }, { sel, id: pick.id, mobile });
      check(Math.abs(now.top - pick.top) <= 2 && now.st > 0 && now.open === (step === "expand"),
            `${mobile ? "phone" : "desktop"} calls ${step}: clicked row moved ${Math.round(now.top - pick.top)}px (scrollTop ${pick.st} → ${now.st})`);
    }
    await p.close();
  }
  // ── Calls: a new call arriving by the live poll (5 s) slides in on top; existing rows and the gauge are untouched ──
  for (const [w, h, mobile] of [[1440, 900, false], [420, 860, true]]) {
    const { p } = await page(browser, w, h);
    await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });
    await p.waitForTimeout(900);
    const before = await p.evaluate(() => {
      const list = document.querySelector(".mtt-list"), rows = [...list.querySelectorAll("[data-id]")];
      window.__old = new Map(rows.slice(0, 30).map((r) => [r.dataset.id, r]));
      window.__minRows = rows.length; window.__gauge = [];
      const g = document.querySelector(".mtt-gauge"), count = () => list.querySelectorAll("[data-id]").length;
      new MutationObserver(() => { window.__minRows = Math.min(window.__minRows, count()); window.__gauge.push(g.getBoundingClientRect().height); })
        .observe(document.querySelector(".mtt"), { childList: true, subtree: true });
      return { rows: rows.length, gauge: g.getBoundingClientRect().height };
    });
    await p.evaluate(() => { window.__arrivals = 1; });
    await p.waitForFunction(() => document.querySelector('.mtt-list [data-id="new-0"]'), null, { timeout: 8000 }).catch(() => {});
    await p.waitForTimeout(300);
    const r = await p.evaluate(() => {
      const list = document.querySelector(".mtt-list"), first = list.querySelector("[data-id]");
      let kept = 0, lost = 0;
      window.__old.forEach((node, id) => { if (list.querySelector(`[data-id="${id}"]`) === node) kept++; else lost++; });
      return { first: first && first.dataset.id, kept, lost, minRows: window.__minRows, gauge: window.__gauge.length ? Math.min(...window.__gauge) : null };
    });
    const tag = mobile ? "phone" : "desktop";
    check(r.first === "new-0", `${tag} calls: the arriving call is shown on top (first row ${r.first})`);
    check(r.lost === 0, `${tag} calls: ${r.lost} unchanged rows were re-created by the live update (kept ${r.kept})`);
    check(r.minRows >= before.rows, `${tag} calls: the list flashed down to ${r.minRows} rows during the update`);
    check(r.gauge == null || r.gauge >= before.gauge - 1, `${tag} calls: the gauge collapsed to ${r.gauge}px (was ${before.gauge}px) during the refresh`);
    await p.close();
  }
  // ── hover marquee: only an overflowing name moves, at a distance-based pace, eases back on leave; reduced motion: none ──
  for (const reduce of [false, true]) {
    const { p } = await page(browser, 1500, 900);
    if (reduce) await p.emulateMedia({ reducedMotion: "reduce" });
    await p.evaluate(() => { window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
    await p.waitForTimeout(700);
    const geo = (id) => p.evaluate((id) => { const st = document.querySelector(`.mti-ses[data-id="${id}"] .mti-st`), b = st.getBoundingClientRect(), r = st.parentElement.getBoundingClientRect();
      const sp = st.querySelector(".mt-mq"), m = sp && /translateX\((-?[\d.]+)px\)/.exec(sp.style.transform);
      return { w: Math.round(b.width), h: Math.round(r.height), x: sp ? +new DOMMatrix(getComputedStyle(sp).transform).m41.toFixed(1) : 0, target: m ? +m[1] : 0,
        dur: sp ? parseFloat(getComputedStyle(sp).transitionDuration) : 0, text: st.textContent, over: st.scrollWidth - st.clientWidth }; }, id);
    const rest = await geo("b");
    await p.hover('.mti-ses[data-id="b"] .mti-st'); await p.waitForTimeout(1400);
    const mid = await geo("b");
    await p.hover('.mti-ses[data-id="a"] .mti-st'); await p.waitForTimeout(700);
    const short = await geo("a"), back = await geo("b");
    if (reduce) check(mid.x === 0 && !mid.target, `reduced motion: the name must not move (${JSON.stringify(mid)})`);
    else {
      check(rest.over > 20 && mid.x < -5 && mid.target < 0, `long name glides while hovered (${JSON.stringify({ rest, mid })})`);
      check(Math.abs(mid.dur - Math.max(1.2, (-mid.target) / 45)) < 0.05, `pace follows the overflow distance (~45 px/s): ${mid.dur}s for ${-mid.target}px`);
      check(mid.w === rest.w && mid.h === rest.h, `no layout change while gliding (${rest.w}x${rest.h} → ${mid.w}x${mid.h})`);
      check(short.x === 0 && !short.target, "a name that fits never moves");
      check(back.x === 0 && back.text === rest.text && !back.target, `on leave it returns and the plain (ellipsized) name is restored (${JSON.stringify(back)})`);
    }
    await p.close();
  }
  // ── manual "refresh view" (the tab's ↻: unmount + mount on the same element) with context bars already shown:
  //    nothing below the gauge may move while the remounted view reloads, frame by frame, desktop and phone ──
  for (const [view, w, h] of [["telemetry", 1440, 900], ["telemetry", 420, 860], ["inspector", 1440, 900], ["inspector", 420, 860]]) {
    const { p } = await page(browser, w, h);
    const mountIt = (v) => p.evaluate((v) => {
      const el = document.getElementById("mount");
      window.cleanup = (v === "telemetry" ? window.ui.mountTelemetry : window.ui.mountInspector)(el, v === "telemetry" ? {} : { session: "a", mode: "transcript" });
    }, v);
    await mountIt(view); await p.waitForTimeout(1200);
    const probe = view === "telemetry" ? ".mtt-list" : ".mti-body";
    const bars = await p.evaluate((v) => document.querySelectorAll((v === "telemetry" ? ".mtt-gauge" : ".mti-gauge") + " .mtt-g").length, view);
    const tops = await p.evaluate(async ({ v, probe }) => {
      const top = () => { const e = document.querySelector(probe); return e ? Math.round(e.getBoundingClientRect().top + document.scrollingElement.scrollTop) : null; };
      const before = top();
      window.__slow = 500;
      const el = document.getElementById("mount");
      window.cleanup(); el.innerHTML = "";  // exactly what the tab's reload does
      window.cleanup = (v === "telemetry" ? window.ui.mountTelemetry : window.ui.mountInspector)(el, v === "telemetry" ? {} : { session: "a", mode: "transcript" });
      const seen = [];
      for (let f = 0; f < 110; f++) { seen.push(top()); await new Promise((r) => requestAnimationFrame(r)); }
      window.__slow = 0;
      return { before, seen };
    }, { v: view, probe });
    const moved = tops.seen.filter((x) => x != null && Math.abs(x - tops.before) > 1);
    check(bars > 0, `${view} ${w}: context bars were shown before the refresh`);
    check(!moved.length, `${view} ${w}: manual refresh moved the content below the gauge (${tops.before} → ${[...new Set(tops.seen)].join(",")})`);
    await p.close();
  }
  // ── general call errors in a real browser: failed / recovered / no status / SDK code, 429 kept, the error filter,
  //    desktop table and phone cards (no horizontal overflow) ──
  for (const [w, h, mobile] of [[1440, 900, false], [420, 860, true]]) {
    const { p } = await page(browser, w, h);
    await p.evaluate(() => {
      const sum = (st, nf) => { const n = typeof st === "number" ? st : null, failed = n != null && !(n >= 200 && n < 300), ok = n != null && n >= 200 && n < 300;
        return { v: 1, scope: "call", outcome: failed ? "failed" : ok ? "succeeded" : "unknown", category: !failed ? null : n === 0 ? "transport_or_invalid_response" : n === 429 ? "rate_limit" : n >= 500 ? "server" : "http",
          affected: failed || nf > 0, recovered: ok && nf > 0, recorded_failure_observations: nf }; };
      const set = { "call-0": [0, 1, 0], "call-1": [429, 2, 2], "call-2": [503, 1, 0], "call-3": [200, 2, 1], "call-4": [null, null, 0], "call-5": ["insufficient_quota", null, 0] };
      const orig = window.__HERMES_PLUGIN_SDK__.fetchJSON;
      window.__HERMES_PLUGIN_SDK__.fetchJSON = (url) => orig(url).then((d) => {
        if (/\/calls\?/.test(url) && d.rows) {
          d.rows.forEach((r) => { const v = set[r.id]; if (v) Object.assign(r, { status: v[0], nfail: v[1], n429: v[2] }); r.error_summary = sum(r.status, r.nfail); });
          if (/errors=1/.test(url)) d.rows = d.rows.filter((r) => r.error_summary.affected);
        }
        return d;
      });
      window.ui.mountTelemetry(document.getElementById("mount"), {});
    });
    await p.waitForTimeout(900);
    const sel = mobile ? ".mtt-call" : ".mtt-calls tbody tr";
    const chips = await p.evaluate((sel) => Object.fromEntries([...document.querySelectorAll(sel + "[data-id]")].slice(0, 7).map((r) => [r.dataset.id, (r.querySelector(".mtt-err") || { textContent: "" }).textContent])), sel);
    const want = { "call-0": "failed · transport / invalid response", "call-1": "failed · rate limit 429", "call-2": "failed · server 503", "call-3": "recovered · 2 obs · 429",
      "call-4": "no status", "call-5": "code insufficient_quota", "call-6": "" };
    const tag = mobile ? "phone" : "desktop";
    check(JSON.stringify(chips) === JSON.stringify(want), `${tag} error chips ${JSON.stringify(chips)}`);
    if (mobile) {
      const over = await p.evaluate(() => [...document.querySelectorAll(".mtt-call")].slice(0, 7).some((c) => c.scrollWidth > c.clientWidth + 1));
      check(!over, "phone: error chips do not overflow their card");
    }

    for (const [v, ids] of [["any", "call-0,call-1,call-2,call-3"], ["failed", "call-0,call-1,call-2"], ["recovered", "call-3"]]) {
      await p.selectOption('[data-c="errs"]', v); await p.waitForTimeout(400);
      const got = await p.evaluate((sel) => [...document.querySelectorAll(sel + "[data-id]")].map((r) => r.dataset.id).filter((x) => /^call-[0-6]$/.test(x)).join(","), sel);
      check(got === ids, `${tag} errors filter "${v}" → ${got} (want ${ids})`);
    }
    await p.close();
  }
  // ── toolbar design: help / phone-filters popovers and every filter toggle leave the layout where it was (frame by
  //    frame); the popover sits inside the viewport; Esc returns focus; the live badge's state changes move nothing ──
  const docTop = (sel) => `(() => { const e = document.querySelector(${JSON.stringify(sel)}); return e ? Math.round(e.getBoundingClientRect().top + document.scrollingElement.scrollTop) : null; })()`;
  async function still(p, sel, act, frames = 14) {
    return p.evaluate(async ({ sel, act, frames, docTopSrc }) => {
      const top = () => eval(docTopSrc);
      const before = top(), seen = [];
      eval(act);
      for (let f = 0; f < frames; f++) { await new Promise((r) => requestAnimationFrame(r)); seen.push(top()); }
      return { before, moved: seen.filter((x) => x != null && Math.abs(x - before) > 1) };
    }, { sel, act, frames, docTopSrc: docTop(sel) });
  }
  for (const [view, w, h] of [["inspector", 1440, 900], ["inspector", 1280, 800], ["inspector", 420, 860], ["inspector", 360, 780],
                              ["telemetry", 1440, 900], ["telemetry", 1280, 800], ["telemetry", 420, 860], ["telemetry", 360, 780]]) {
    const { p, errors } = await page(browser, w, h);
    const ins = view === "inspector", phone = w <= 768, tag = `${view} ${w}`;
    try {
    await p.evaluate((ins) => { window.cleanup = (ins ? window.ui.mountInspector : window.ui.mountTelemetry)(document.getElementById("mount"), ins ? { session: "a", mode: "transcript" } : {}); }, ins);
    await p.waitForTimeout(1100);
    await p.evaluate(() => { document.scrollingElement.scrollTop = 0; }); await p.waitForTimeout(100);  // phones open at the newest row
    const probe = ins ? ".mti-body" : ".mtt-gauge", scope = ins ? ".mti-top" : ".mtt";
    const head = () => p.evaluate((s) => Math.round(document.querySelector(s).getBoundingClientRect().height), ins ? ".mti-top" : ".mtt-filters");
    const h0 = await head();
    for (const trig of [".mti-help"]) {
      const sel = `${scope} ${trig}`;
      const tr0 = await p.evaluate((s) => { const b = document.querySelector(s).getBoundingClientRect(); return [Math.round(b.x), Math.round(b.y + scrollY)]; }, sel);
      const r = await still(p, probe, `document.querySelector(${JSON.stringify(sel)}).click()`);
      check(!r.moved.length, `${tag}: opening ${trig} moved the content (${r.before} → ${[...new Set(r.moved)]})`);
      const pop = await p.evaluate((s) => {
        const t = document.querySelector(s), id = t.getAttribute("aria-controls"), el = document.getElementById(id), b = el.getBoundingClientRect(), tb = t.getBoundingClientRect();
        return { open: !el.hidden && t.getAttribute("aria-expanded") === "true", l: b.left, r: b.right, t: b.top, vw: document.documentElement.clientWidth, x: Math.round(tb.x), y: Math.round(tb.y + scrollY) };
      }, sel);
      check(pop.open && pop.l >= 0 && pop.r <= pop.vw + 1 && pop.t >= 0, `${tag}: ${trig} popover open inside the viewport (${JSON.stringify(pop)})`);
      check(pop.x === tr0[0] && pop.y === tr0[1], `${tag}: ${trig} did not move out from under the pointer (${tr0} → ${pop.x},${pop.y})`);
      await p.keyboard.press("Escape"); await p.waitForTimeout(80);
      const closed = await p.evaluate((s) => { const t = document.querySelector(s); return { hidden: document.getElementById(t.getAttribute("aria-controls")).hidden, focus: document.activeElement === t }; }, sel);
      check(closed.hidden && closed.focus, `${tag}: Esc closes ${trig} and focus returns to it (${JSON.stringify(closed)})`);
      check(await head() === h0, `${tag}: header height changed after ${trig} open/close (${h0} → ${await head()})`);
    }
    // every filter / behaviour toggle: nothing below the toolbar moves while it applies
    const toggles = ins ? ['[data-f="tools"]', '[data-f="inactive"]', '[data-f="flag"]', '[data-rows="all"]', '[data-f="live"]']
      : ['[data-c="misses"]', '[data-c="slow"]', '[data-c="misses"]', '[data-c="slow"]', '[data-c="auto"]'];
    for (const t of toggles) {
      const r = await still(p, probe, `document.querySelector(${JSON.stringify(t)}).click()`, 20);
      check(!r.moved.length, `${tag}: toggling ${t} moved the content (${r.before} → ${[...new Set(r.moved)]})`);
    }
    check(await head() === h0, `${tag}: toolbar height drifted across toggles (${h0} → ${await head()})`);
    if (ins && !phone) {  // honest badge: scrolled away from the latest item → paused, and why; the badge box keeps its width
      await p.evaluate(() => { const s = document.querySelector('[data-f="live"]'); if (!s.checked) s.click(); });  // back on (toggled off above)
      const b0 = await p.evaluate(() => { const b = document.querySelector(".mt-live").getBoundingClientRect(); return [Math.round(b.x), Math.round(b.width)]; });
      await p.evaluate(() => { document.querySelector(".mti-tl").scrollTop = 0; }); await p.waitForTimeout(150);
      const b1 = await p.evaluate(() => { const e = document.querySelector(".mt-live"), b = e.getBoundingClientRect(); return [Math.round(b.x), Math.round(b.width), e.textContent]; });
      check(b1[2] === "paused" && /scroll/.test(await p.evaluate(() => document.querySelector(".mt-live").title)), `on but paused: one word, the reason in its tooltip (${b1[2]})`);
      check(b1[0] === b0[0] && b1[1] === b0[1], `badge state change moved it (${b0} → ${b1})`);
    }
    if (phone) {  // touch targets
      const small = await p.evaluate((ins) => {
        const min = 2.4 * parseFloat(getComputedStyle(document.documentElement).fontSize) - 0.5;  // 2.4rem in this host
        return [...document.querySelectorAll(ins ? ".mti-top .mti-help, .mti-top .mt-switch, .mti-top .mt-segb, .mti-top .mt-tog, .mti-q, .mti-top .mt-tab, .mti-sbbtn"
          : ".mtt .mti-help, .mtt .mt-switch, .mtt .mt-tog, .mtt-filters select, .mtt-sessq, .mtt-tabs .mt-tab")].filter((e) => e.getBoundingClientRect().height < min).map((e) => e.className);
      }, ins);
      check(!small.length, `${tag}: touch targets under 2.4rem: ${small}`);
    }
    if (ins && phone) {  // the gauge key line scrolls sideways; its items never overprint each other
      const ov = await p.evaluate(() => {
        const r = [...document.querySelectorAll(".mti-gauge .mtt-gk > *")].map((e) => e.getBoundingClientRect());
        return r.some((a, i) => i && a.left < r[i - 1].right - 0.5);
      });
      check(!ov, `${tag}: gauge key items overlap`);
    }
    check(!errors.length, `${tag}: page errors ${errors}`);
    } catch (e) { check(false, `${tag}: toolbar checks threw: ${e.message.split("\n")[0]}`); }
    await p.close();
  }
  // ── family tabs: any count fits — All and Sessions stay fully visible (pinned), the strip scrolls with edge fades,
  //    one fixed height; the selected family is scrolled into view; ← / → keep the focused tab visible ──
  const LABELS = ["Claude", "OpenAI", "Gemini", "DeepSeek Reasoner", "Mistral", "Qwen", "Grok", "Kimi", "Llama Local", "MiniMax", "Cohere", "Phi", "Gemma", "Nova", "Yi"];
  for (const w of [1440, 1280, 420, 360]) {
    const hs = [];
    for (const n of [1, 4, 8, 15]) {
      const { p } = await page(browser, w, 820);
      try {
      await p.evaluate((f) => { window.__fams = f; }, LABELS.slice(0, n).map((label, i) => ({ family: "f" + i, label, n: 100 - i })));
      await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });
      await p.waitForTimeout(800);
      const g = await p.evaluate(() => {
        const s = document.querySelector(".mtt-fstrip"), sr = s.getBoundingClientRect(), vw = document.documentElement.clientWidth;
        const pin = (t) => { const b = document.querySelector(`.mtt-pin[data-t="${t}"]`).getBoundingClientRect(); return b.left >= 0 && b.right <= vw + 0.5 && b.width > 20; };
        return { all: pin("all"), ses: pin("sessions"), h: Math.round(document.querySelector(".mtt-controls").getBoundingClientRect().height),
          over: s.scrollWidth > s.clientWidth + 1, fadeR: s.classList.contains("is-r"), tabs: s.querySelectorAll(".mt-tab").length, sr: [sr.left, sr.right] };
      });
      hs.push(g.h);
      check(g.all && g.ses, `tabs ${w}/${n}: All or Sessions not fully visible (${JSON.stringify(g)})`);
      check(g.tabs === n, `tabs ${w}/${n}: ${g.tabs} family tabs (want every family, no Other)`);
      check(!g.over || g.fadeR, `tabs ${w}/${n}: overflowing strip shows no right-edge fade`);
      // select the last family: it is scrolled fully into the strip's view; then ← from Sessions reaches it visibly too
      await p.evaluate(() => { [...document.querySelectorAll(".mtt-fstrip .mt-tab")].pop().click(); }); await p.waitForTimeout(600);
      const vis = await p.evaluate(() => { const s = document.querySelector(".mtt-fstrip").getBoundingClientRect(), b = document.querySelector(".mtt-fstrip .mt-tab.is-on").getBoundingClientRect(); return b.left >= s.left - 1 && b.right <= s.right + 1; });
      check(vis, `tabs ${w}/${n}: the selected last family is not scrolled into view`);
      await p.focus('.mtt-pin[data-t="all"]'); await p.keyboard.press("ArrowRight");
      const kv = await p.evaluate(() => { const s = document.querySelector(".mtt-fstrip").getBoundingClientRect(), a = document.activeElement, b = a.getBoundingClientRect(); return { t: a.dataset.t, ok: b.left >= s.left - 1 && b.right <= s.right + 1 }; });
      check(kv.t === "f0" && kv.ok, `tabs ${w}/${n}: → from All focuses the first family, visible (${JSON.stringify(kv)})`);
      } catch (e) { check(false, `tabs ${w}/${n}: threw: ${e.message.split("\n")[0]}`); }
      await p.close();
    }
    check(new Set(hs).size === 1, `tabs ${w}: the tab row height depends on the family count (${hs})`);
  }
  // ── keyboard focus is visible on every toolbar control (incl. visually hidden inputs and JSON-tree summaries);
  //    reduced motion turns transitions off ──
  {
    const { p } = await page(browser, 1440, 900);
    try {
    await p.evaluate(() => {
      const m = document.getElementById("mount");
      window.ui.mountInspector(m, { session: "a", mode: "transcript" });
      const j = document.createElement("div"); j.className = "mtj"; j.innerHTML = "<details><summary>json key</summary>x</details>"; document.querySelector(".mti-top").prepend(j);
    });
    await p.waitForTimeout(900);
    await p.evaluate(() => document.activeElement && document.activeElement.blur());
    const bad = [];
    for (let i = 0; i < 16; i++) {
      await p.keyboard.press("Tab");
      const r = await p.evaluate(() => {
        const a = document.activeElement; if (!a || !a.closest(".mti-top")) return null;
        const ring = (e) => { const cs = getComputedStyle(e); return cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) >= 2; };
        const host = a.matches("input[type=checkbox], input[type=radio]") ? (a.closest(".mt-switch") ? a.closest(".mt-switch").querySelector(".mt-swt") : a.closest("label")) : a;
        return { what: a.className || a.tagName, ok: ring(host) };
      });
      if (r && !r.ok) bad.push(r.what);
    }
    check(!bad.length, `no visible focus ring on: ${bad}`);
    await p.setViewportSize({ width: 1280, height: 800 }); await p.waitForTimeout(200);  // drawer width: the sessions sheet slides
    const live = await p.evaluate(() => [getComputedStyle(document.querySelector(".mt-swt"), "::after").transitionDuration, getComputedStyle(document.querySelector(".mti-sb")).transitionDuration]);
    check(live.every((d) => d !== "0s"), `motion is on by default (precondition) (${live})`);
    await p.emulateMedia({ reducedMotion: "reduce" });
    const dur = await p.evaluate(() => [getComputedStyle(document.querySelector(".mt-swt"), "::after").transitionDuration, getComputedStyle(document.querySelector(".mti-sb")).transitionDuration]);
    check(dur.every((d) => d === "0s"), `reduced motion: transitions still run (${dur})`);
    } catch (e) { check(false, `focus / reduced-motion checks threw: ${e.message.split("\n")[0]}`); }
    await p.close();
  }
  // ── tags never act; navigation is an underlined inline link with an arrow, or a conventional labelled button
  //    (desktop and phone; phone tap height ≥ 2rem); a real click / Enter on the refresh badge changes no filter ──
  for (const [w, h] of [[1440, 900], [420, 860]]) {
    const { p } = await page(browser, w, h);
    try {
      await p.evaluate(() => { window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
      await p.waitForTimeout(900);
      const r = await p.evaluate(() => {
        const links = [...document.querySelectorAll('[data-a="towire"], [data-a="clatest"], [data-a="after"]')];
        const rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
        return {
          n: links.length,
          bad: links.filter((x) => {
            const cs = getComputedStyle(x);
            if (x.matches(".mt-btn:not(.mt-chip)")) return !/\w.*[→↓]/.test(x.textContent);  // labelled button: words + arrow
            return !x.matches(".mt-link") || !cs.textDecorationLine.includes("underline") || cs.borderTopStyle !== "none" || !/[→↓]/.test(x.textContent);
          }).map((x) => x.className),
          short: innerWidth <= 768 ? links.filter((x) => x.getBoundingClientRect().height < 2 * rem - 0.5).length : 0,
          tags: [...document.querySelectorAll(".mt-chip")].filter((x) => x.matches("button, a, [tabindex], [data-a]")).length,
        };
      });
      check(r.n > 0 && !r.bad.length && !r.tags && !r.short, `${w}: navigation must be underlined links, tags must not act (${JSON.stringify(r)})`);
      await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });  // remount as Calls
      await p.waitForTimeout(900);
      const q0 = await p.evaluate(() => document.querySelector('[data-c="sess"]').value);
      await p.click(".mtt .mt-live"); await p.keyboard.press("Enter"); await p.waitForTimeout(300);
      const q1 = await p.evaluate(() => ({ s: document.querySelector('[data-c="sess"]').value, t: (document.querySelector(".mtt-tabs .mt-tab.is-on") || {}).dataset }));
      check(q1.s === q0 && q1.t && q1.t.t === "all", `${w}: a real click + Enter on the refresh badge changed the filters (${JSON.stringify(q1)})`);
    } catch (e) { check(false, `${w}: tag/link checks threw: ${e.message.split("\n")[0]}`); }
    await p.close();
  }
  // ── popover lifecycle (the phone "filters" menu could not be closed: a CSS rule beat [hidden]). Real taps / clicks /
  //    keys, both views, desktop and phone: ? again, a press outside, Esc, a mode switch and a view switch (unmount +
  //    mount, as the dashboard tab does) each leave zero visible popovers and exactly one overlay layer. ──
  const visiblePops = (p) => p.evaluate(() => [...document.querySelectorAll(".mt-layer *")].filter((e) =>
    (e.hidden || e.matches(".mt-pop")) && getComputedStyle(e).display !== "none" && e.getBoundingClientRect().height > 0).map((e) => e.id || e.className));
  for (const [w, h, phone] of [[1440, 900, false], [420, 860, true]]) {
    const { p: q, errors } = await page(browser, w, h, phone);
    try {
      const tag = `${phone ? "phone" : "desktop"} popovers`;
      const press = async (sel) => { if (phone) await q.tap(sel); else await q.click(sel); };
      await q.evaluate(() => { window.cleanup = window.ui.mountInspector(document.getElementById("mount"), { session: "a", mode: "transcript" }); });
      await q.waitForTimeout(900);
      await q.evaluate(() => { document.scrollingElement.scrollTop = 0; });
      check(!(await visiblePops(q)).length, `${tag}: a popover is visible after load (${await visiblePops(q)})`);
      // "outside" = a neutral spot above the toolbar (the host header), not a message row (that opens its detail sheet)
      const neutral = async () => { if (phone) await q.touchscreen.tap(12, 20); else await q.mouse.click(12, 20); };
      for (const [how, close] of [["? again", () => press(".mti-help")], ["press outside", neutral],
                                  ["Esc", () => q.keyboard.press("Escape")], ["mode switch", () => press('[data-mode="wire"]')]]) {
        await q.evaluate(() => { document.scrollingElement.scrollTop = 0; });
        await press(".mti-help"); await q.waitForTimeout(150);
        const open = await visiblePops(q);
        await close(); await q.waitForTimeout(250);
        const after = await visiblePops(q);
        check(open.length === 1 && !after.length, `${tag}: ${how} left a popover open (open ${open}, after ${after})`);
      }
      // view switch while help is open: what the dashboard tab does (cleanup, then mount the other view)
      await q.evaluate(() => { document.scrollingElement.scrollTop = 0; });
      await press(".mti-help"); await q.waitForTimeout(150);
      await q.evaluate(() => { window.cleanup(); document.getElementById("mount").innerHTML = ""; window.cleanup = window.ui.mountTelemetry(document.getElementById("mount"), {}); });
      await q.waitForTimeout(700);
      const layers = await q.evaluate(() => document.querySelectorAll(".mt-layer").length);
      check(!(await visiblePops(q)).length && layers === 1, `${tag}: a view switch left ${layers} overlay layers / visible ${await visiblePops(q)}`);
      await q.evaluate(() => { document.scrollingElement.scrollTop = 0; });
      await press(".mtt .mti-help"); await q.waitForTimeout(150);
      await press('.mtt-pin[data-t="sessions"]'); await q.waitForTimeout(400);
      check(!(await visiblePops(q)).length, `${tag}: a Calls tab change left help open (${await visiblePops(q)})`);
      await q.evaluate(() => { window.cleanup(); document.getElementById("mount").innerHTML = ""; });
      const left = await q.evaluate(() => document.querySelectorAll(".mt-layer, .mt-pop").length);
      check(left === 0, `${tag}: unmount left ${left} overlay nodes in <body>`);
      check(!errors.length, `${tag}: page errors ${errors}`);
    } catch (e) { check(false, `popover lifecycle threw: ${e.message.split("\n")[0]}`); }
    await q.close();
  }
  // ── Calls phone toolbar type and widths: inputs/selects use the toolbar's type size, not 16px; the
  //    window select is compact and narrower than the errors select; no select clips its own value ──
  for (const [w, h] of [[420, 860], [360, 780]]) {
    const { p } = await page(browser, w, h, true);
    try {
      await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });
      await p.waitForTimeout(900);
      const r = await p.evaluate(() => {
        const fs = (s) => parseFloat(getComputedStyle(document.querySelector(s)).fontSize);
        const wd = (s) => Math.round(document.querySelector(s).getBoundingClientRect().width);
        const clip = [...document.querySelectorAll(".mtt-filters select")].filter((s) => s.scrollWidth > s.clientWidth + 1).map((s) => s.dataset.c);
        return { tab: fs(".mtt-tabs .mt-tab"), sess: fs(".mtt-sessq"), win: fs('[data-c="hours"]'), errs: fs('[data-c="errs"]'), ww: wd('[data-c="hours"]'), we: wd('[data-c="errs"]'), clip };
      });
      check(Math.max(r.sess, r.win, r.errs) <= r.tab + 1.5, `${w}: toolbar inputs larger than the tabs (${JSON.stringify(r)})`);
      check(r.ww <= 90 && r.ww < r.we && !r.clip.length, `${w}: window select too wide or a select clips (${JSON.stringify(r)})`);
    } catch (e) { check(false, `${w}: Calls toolbar sizing threw: ${e.message.split("\n")[0]}`); }
    await p.close();
  }
  // ── held new calls while a call is expanded (review P2, cf58c31): no pending → pending → apply. The toolbar height
  //    and the expanded call's on-screen top stay put at every step, at 360 / 420 / 1280 / 1440 ──
  for (const [w, h] of [[360, 780], [420, 860], [1280, 800], [1440, 900]]) {
    const phone = w <= 768, { p, errors } = await page(browser, w, h, phone);
    try {
      await p.evaluate(() => { window.ui.mountTelemetry(document.getElementById("mount"), {}); });
      await p.waitForTimeout(900);
      const sel = phone ? ".mtt-call" : ".mtt-calls tbody tr";
      await p.evaluate((sel) => document.querySelector(`${sel}[data-id="call-2"]`).dispatchEvent(new MouseEvent("click", { bubbles: true })), sel);
      await p.waitForTimeout(250);
      const geo = () => p.evaluate((sel) => ({ bar: Math.round(document.querySelector(".mtt-filters").getBoundingClientRect().height * 10) / 10,
        top: Math.round(document.querySelector(`${sel}[data-id="call-2"]`).getBoundingClientRect().top * 10) / 10,
        open: !!document.querySelector(".mtt-det"), pending: !!document.querySelector('[data-a="applynew"]') }), sel);
      const g0 = await geo();
      await p.evaluate(() => { window.__arrivals = 1; });
      await p.waitForFunction(() => document.querySelector('[data-a="applynew"]'), null, { timeout: 9000 });
      await p.waitForTimeout(200);
      const g1 = await geo();
      await p.click('[data-a="applynew"]'); await p.waitForTimeout(300);
      const g2 = await geo();
      const tag = `${w} held new calls`;
      check(g0.open && g1.pending && !g2.pending && g2.open, `${tag}: scenario did not run (${JSON.stringify([g0, g1, g2])})`);
      check(Math.abs(g1.bar - g0.bar) <= 0.5 && Math.abs(g1.top - g0.top) <= 0.5, `${tag}: the notice moved the toolbar / expanded call (${JSON.stringify([g0, g1])})`);
      check(Math.abs(g2.bar - g0.bar) <= 0.5 && Math.abs(g2.top - g0.top) <= 1, `${tag}: applying moved the toolbar / expanded call (${JSON.stringify([g0, g2])})`);
      check(!errors.length, `${tag}: page errors ${errors}`);
    } catch (e) { check(false, `${w}: held-new-calls check threw: ${e.message.split("\n")[0]}`); }
    await p.close();
  }
} finally { await browser.close(); }
for (const n of notes) console.error(n);
if (fails.length) { console.log("FAIL\n" + fails.join("\n")); process.exit(1); }
console.log("ok: columns reach their end (desktop sizes, late banner, resize, phone), panes stay put across loads/switch/Wire, calls rows keep their place");
