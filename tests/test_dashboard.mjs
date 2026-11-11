// Dashboard regression checks run by test_wiretap.DashboardJsTest under jsdom (no browser, no network):
// the real dist/index.js bundle mounted against a stub SDK whose fetchJSON returns promises the test resolves in
// any order. Usage: node test_dashboard.mjs <index.js> <dir containing node_modules/jsdom>
import { createRequire } from "module";
import { readFileSync } from "fs";
import path from "path";

const [, , bundle, jsdomFrom] = process.argv;
const { JSDOM } = createRequire(path.join(jsdomFrom, "package.json"))("jsdom");
const fails = [];
const check = (ok, msg) => { if (!ok) fails.push(msg); };
const tick = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

function boot(internals) {
  const dom = new JSDOM('<!doctype html><body><div id="root"></div></body>', { runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  const pending = [];
  w.__HERMES_PLUGIN_SDK__ = {
    React: { createElement() { return null; } }, hooks: { useState() { return [null, () => {}]; }, useEffect() {}, useRef() { return {}; } },
    fetchJSON: (url) => new Promise((res, rej) => pending.push({ url, res, rej })),
  };
  w.__HERMES_PLUGINS__ = { register() {} };
  let api = null;
  w.__WIRETAP_TEST__ = { expose(x) { api = x; } };
  w.matchMedia = w.matchMedia || (() => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  w.IntersectionObserver = undefined;
  let src = readFileSync(bundle, "utf8");
  if (internals) {  // test-only: reach the mounted views' state and loaders (as the review's probe does)
    w.setInterval = () => 0; w.requestAnimationFrame = () => 0; w.HTMLElement.prototype.scrollIntoView = function () {};
    src = src.replace("mountTelemetry: mountTelemetry, partKey:", "mountInspector: mountInspector, mountTelemetry: mountTelemetry, partKey:")
      .replace("    return function () {\n      S.alive = false;", "    window.probeS = { S: S, loadCompiled: loadCompiled, part: part };\n    return function () {\n      S.alive = false;")
      .replace("    return function () {\n      T.alive = false;", "    window.probeT = { T: T, load: load };\n    return function () {\n      T.alive = false;");
  }
  w.eval(src);
  return { w, pending, api, root: w.document.getElementById("root") };
}

function callsPayload(marker, n, more) {
  const rows = [];
  for (let i = 0; i < n; i++) {
    rows.push({ id: `h:${marker}:${i}`, source: "hermes", started: 1e9 + i, model: `model-${marker}`, family: "claude", provider: "p",
                session_id: "s", status: 200, events: [], prompt_tokens: 100, cached_tokens: 50, output_tokens: 5 });
  }
  return { rows, offset: 0, has_more: !!more, total: more ? n * 2 : n, rev: `rev-${marker}`, summary: {}, agg: [], keys: [], fail_keys: [],
           families: [{ family: "claude", label: "Claude", n }], providers: [], last_scan: {}, last_capture: {}, oldest: 1e9, now: 1e9 };
}
const take = (pending, re) => { const i = pending.findIndex((p) => re.test(p.url)); return i < 0 ? null : pending.splice(i, 1)[0]; };
// Convention: a tag (.mt-chip) only describes — it is never a control, never focusable, never carries an action;
// navigation is an inline link (.mt-link) and actions are labelled buttons. Returns the offenders.
const actingTags = (root) => [...root.querySelectorAll(".mt-chip")].filter((x) =>
  x.matches("button, a, [tabindex], [data-a], [role=button], [role=link]") || x.closest("button.mt-chip, a.mt-chip")).map((x) => x.outerHTML.slice(0, 90));
const navNotLink = (root) => [...root.querySelectorAll('[data-a="towire"], [data-a="clatest"], [data-a="after"], [data-a="torow"]')]
  .filter((x) => !(x.matches("button.mt-link, a.mt-link") || (x.matches(".mt-btn") && !x.matches(".mt-chip")))).map((x) => x.outerHTML.slice(0, 90));

// 1. Calls & Cache: responses arriving out of order never overwrite a newer filter's data.
{
  const { w, pending, api, root } = boot();
  check(api && api.mountTelemetry, "bundle exposes mountTelemetry under __WIRETAP_TEST__");
  api.mountTelemetry(root);
  await tick();
  take(pending, /\/calls\?/).res(callsPayload("init", 3));
  await tick();
  const s = take(pending, /\/sessions\?/); if (s) s.res({ main: null, sessions: [] });
  await tick();
  check(root.innerHTML.includes("model-init"), "initial page rendered");
  const box = root.querySelector('[data-c="misses"]');
  box.checked = true; box.dispatchEvent(new w.Event("change", { bubbles: true }));   // load A (misses on)
  await tick();
  box.checked = false; box.dispatchEvent(new w.Event("change", { bubbles: true }));  // load B (misses off) — newest
  await tick();
  const calls = pending.filter((p) => /\/calls\?/.test(p.url));
  check(calls.length === 2, `two loads in flight (got ${calls.length})`);
  const A = calls.find((p) => /misses=1/.test(p.url)), B = calls.find((p) => !/misses=1/.test(p.url));
  B.res(callsPayload("newest", 2)); await tick();
  A.res(callsPayload("stale", 2)); await tick();
  check(root.innerHTML.includes("model-newest") && !root.innerHTML.includes("model-stale"),
        "the older filter's late response is dropped");
  pending.splice(0);
}

// 2. "Load older calls": a page that resolves after the list was reloaded is not appended to the new list.
{
  const { w, pending, api, root } = boot();
  api.mountTelemetry(root);
  await tick();
  take(pending, /\/calls\?/).res(callsPayload("first", 3, true));
  await tick();
  const s = take(pending, /\/sessions\?/); if (s) s.res({ main: null, sessions: [] });
  await tick();
  root.querySelector('[data-a="more"]').dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  await tick();
  const page = take(pending, /page=1/);
  check(!!page, "older page requested");
  const box = root.querySelector('[data-c="slow"]');
  box.checked = true; box.dispatchEvent(new w.Event("change", { bubbles: true }));  // the list is reloaded
  await tick();
  take(pending, /\/calls\?/).res(callsPayload("reloaded", 2)); await tick();
  page.res({ rows: callsPayload("oldpage", 2).rows, has_more: false }); await tick();
  check(root.innerHTML.includes("model-reloaded") && !root.innerHTML.includes("model-oldpage"),
        "a stale older page is not appended to the reloaded list");
}

// 3. The wire-part cache key is the request itself: call, layer and every argument.
{
  const { api } = boot();
  const k = api.partKey;
  check(k("h:a", "down", "part=item&i=3") === k("h:a", "down", "part=item&i=3"), "same request, same key");
  check(k("h:a", "down", "part=item&i=3") !== k("h:b", "down", "part=item&i=3"), "another call: another key");
  check(k("h:a", "down", "part=item&i=3") !== k("h:a", "hermes", "part=item&i=3"), "another layer: another key");
}

// 4. copy puts the payload on the clipboard — never a file download — over plain HTTP (no secure context, no
//    navigator.clipboard) synchronously inside the click, and through navigator.clipboard in a secure context.
{
  const { w, api } = boot();
  check(api.jsonPanel && api.copyFrom, "bundle exposes jsonPanel/copyFrom");
  let downloads = 0, copied = null, syncCopy = false, inClick = false;
  w.URL.createObjectURL = () => { downloads++; return "blob:x"; };
  w.HTMLAnchorElement.prototype.click = function () { downloads++; };
  w.document.execCommand = (cmd) => {
    if (cmd !== "copy") return false;
    const el = w.document.activeElement;
    copied = el && el.value != null ? el.value.slice(el.selectionStart, el.selectionEnd) : null;
    syncCopy = inClick;
    return true;
  };
  Object.defineProperty(w, "isSecureContext", { value: false, configurable: true });
  const panel = api.jsonPanel("arguments", { todos: [{ id: "a", status: "done" }] }, { open: 2 });
  w.document.body.appendChild(panel);
  const btn = [...panel.querySelectorAll("button")].find((b) => b.textContent === "copy");
  inClick = true; btn.dispatchEvent(new w.MouseEvent("click", { bubbles: true })); inClick = false;
  check(syncCopy, "plain HTTP: copied synchronously within the click (iOS keeps the gesture)");
  check(copied === JSON.stringify({ todos: [{ id: "a", status: "done" }] }, null, 2), "the whole payload was selected and copied");
  check(btn.textContent === "copied", `feedback shown (got "${btn.textContent}")`);
  check(downloads === 0, "no download");
  w.document.execCommand = () => false;
  const btn2 = api.jsonPanel("x", { a: 1 }, {}).querySelector("button:nth-of-type(3)");
  w.document.body.appendChild(btn2.closest(".mtj-panel"));
  btn2.click();
  check(btn2.textContent === "copy failed", `failure is reported, not hidden (got "${btn2.textContent}")`);
  check(downloads === 0, "still no download after a failed copy");
  // secure context: the async clipboard API
  Object.defineProperty(w, "isSecureContext", { value: true, configurable: true });
  let wrote = null;
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: (t) => { wrote = t; return Promise.resolve(); } }, configurable: true });
  const b3 = document3(w, api);
  b3.click();
  await tick();
  check(wrote === JSON.stringify({ k: "v" }, null, 2) && b3.textContent === "copied", "secure context uses navigator.clipboard");
  check(downloads === 0, "no download in a secure context either");
}
function document3(w, api) {
  const p = api.jsonPanel("y", { k: "v" }, {});
  w.document.body.appendChild(p);
  return [...p.querySelectorAll("button")].find((b) => b.textContent === "copy");
}

// 5. A cached wire part is never served after the same call's stored request changed (adapter input → exact wire):
//    the cache is scoped to the view revision it was read for.
{
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const p = b.w.probeS;
  check(!!p, "inspector internals reachable");
  const comp = (rev, layer) => ({ rev, call_id: "h:a", session: { id: "s" }, wire: { which: "down", layer, meta: { status: 200 }, call: {}, keys: [],
    items: [{ i: 0, role: "user", row_id: null, len: 1, head: "x" }] }, system: {}, rows_after: [] });
  Object.assign(p.S, { sid: "s", gen: 1, comp: comp("old", "hermes"), mode: "wire" });
  const a1 = p.part("part=item&i=0"); take(b.pending, /wire\/part/).res({ payload: "adapter input" }); await a1;
  check((await p.part("part=item&i=0")).payload === "adapter input" && !b.pending.some((x) => /wire\/part/.test(x.url)),
        "same view revision: one fetch");
  const up = p.loadCompiled(true); take(b.pending, /inspector\/compiled/).res(comp("new", "wire")); await up;
  const a2 = p.part("part=item&i=0");
  const req = take(b.pending, /wire\/part/);
  check(!!req, "a new view revision refetches the part");
  if (req) req.res({ payload: "exact wire" });
  check((await a2).payload === "exact wire", "the exact wire is shown, not the cached adapter input");
}

// 6. The Sessions tab: a late response for an older window never overwrites family/provider metadata.
{
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const p = b.w.probeT;
  take(b.pending, /\/calls\?/).res(callsPayload("init", 1)); await tick();
  const s0 = take(b.pending, /\/sessions\?/); if (s0) s0.res({ main: null, sessions: [] }); await tick();
  p.T.tab = "sessions";
  b.root.querySelector('[data-c="hours"]').value = "1";
  const old = p.load();
  const os = take(b.pending, /\/sessions\?hours=1/), oc = take(b.pending, /\/calls\?hours=1/);
  b.root.querySelector('[data-c="hours"]').value = "24";
  const fresh = p.load();
  const ns = take(b.pending, /\/sessions\?hours=24/), nc = take(b.pending, /\/calls\?hours=24/);
  const meta = (m) => Object.assign(callsPayload(m, 1), { families: [{ family: m, label: m, n: 1 }] });
  ns.res({ main: null, sessions: [], tag: "fresh" }); nc.res(meta("fresh-meta")); await fresh;
  os.res({ main: null, sessions: [], tag: "old" }); oc.res(meta("old-meta")); await old;
  check(p.T.sess.tag === "fresh" && p.T.fams[0].family === "fresh-meta", `stale Sessions response ignored (fams=${p.T.fams[0] && p.T.fams[0].family})`);
}

// 7. A split harness item has its own badge/style while its transcript link stays on the human row.
{
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const p = b.w.probeS;
  Object.assign(p.S, { sid: "s", gen: 1, mode: "wire", rows: [
    { id: 42, role: "user", kind: "user", label: "USER · discord", active: true, content: "hi" }
  ] });
  const compiled = p.loadCompiled(true);
  take(b.pending, /inspector\/compiled/).res({ rev: "injection", call_id: "h:injection", session: { id: "s" },
    wire: { which: "down", layer: "wire", meta: { status: 200 }, call: {}, keys: [], items: [
      { i: 0, role: "user", row_id: 42, row_ids: [42], row_kind: "user", row_label: "USER · discord", len: 2, head: "hi" },
      { i: 1, role: "user", row_id: 42, row_ids: [42], row_kind: "user", row_label: "USER · discord",
        item_kind: "internal", item_label: "INJECTED · turn_note", injection_kind: "turn_note",
        len: 40, head: "harness note", framing: "SYSTEM_MESSAGE" }
    ] }, system: {}, rows_after: [] });
  await compiled; await tick();
  const human = b.root.querySelector('[data-ci="item:0"]');
  const note = b.root.querySelector('[data-ci="item:1"]');
  check(human && human.querySelector('.mt-badge').textContent === "USER · discord", "human wire badge unchanged");
  check(note && note.classList.contains('k-internal') && note.querySelector('.mt-badge').textContent === "INJECTED · turn_note",
        "injection badge and kind override parent row provenance");
  check(note && note.textContent.includes("row #42"), "injection retains parent row chip");
  note.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const part = take(b.pending, /wire\/part/);
  if (part) part.res({ role: "user", parts: [{ text: "harness note" }] });
  const rd = take(b.pending, /wire\/readable/);
  check(!!rd && /rows=42(&|$)/.test(rd.url), `Wire › Readable asks for the item's runs against its parent human row (${rd && rd.url})`);
  if (rd) rd.res({ segments: [{ path: "messages[1].parts[0].text", len: 40, runs: [
    { t: "<SYSTEM_MESSAGE>", k: "wrapper", label: "SYSTEM_MESSAGE" }, { t: "harness note", k: "injection", label: "turn_note" },
    { t: "</SYSTEM_MESSAGE>", k: "wrapper", label: "SYSTEM_MESSAGE" }] }], source: ["parts"] });
  await tick();
  const tabs = [...b.w.document.querySelectorAll(".mti-tabs .mt-tab")].map((x) => x.textContent);
  check(tabs.join("|") === "1Readable|2Wire JSON", `a wire item offers exactly Readable | Wire JSON (got ${tabs.join("|")})`);
  const pre = b.w.document.querySelector(".mti-pane pre.mtw");
  check(pre && pre.textContent === "<SYSTEM_MESSAGE>harness note</SYSTEM_MESSAGE>", "one contiguous wire string, exactly as sent");
  check(pre && pre.querySelector(".mtw-inj").textContent === "harness note" && pre.querySelectorAll(".mtw-wrap").length === 2,
        "the injection and its wrapper are highlighted inline");
}

// 13. Call history: the Wire view lists every captured call; picking an older one loads that call, and a transcript
//     chip (+turn_note) jumps to the call that first carried the row, on its injection item.
{
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const p = b.w.probeS;
  const rows = [{ id: 42, role: "user", kind: "user", label: "USER · discord", active: true, content: "hi",
    injections: [{ kind: "turn_note", len: 12 }], framing: { first: { call: "h:one", i: 0, of: 2, framing: "plain" } } },
    { id: 43, role: "assistant", kind: "assistant", label: "ASSISTANT", active: true, content: "ok", wire: "h:one" }];
  const calls = [{ id: "h:one", n: 1, started: 1e9, status: 200, model: "m", lane: "discord" },
    { id: "h:two", n: 2, started: 1e9 + 5, status: 200, model: "m", lane: "discord" },
    { id: "h:rev", n: 3, started: 1e9 + 9, status: 200, model: "m", lane: "review", review: true }];
  const comp = (cid, historic) => ({ rev: "r-" + cid, call_id: cid, correlated_call: cid, latest_call: "h:two", historic, calls, calls_total: 3,
    session: { id: "s" }, system: {}, rows_after: historic ? [{ id: 43, label: "ASSISTANT", kind: "assistant" }] : [],
    wire: { which: "down", layer: "wire", meta: { status: 200 }, call: {}, keys: [], response: { text: "ok", tool_calls: [] }, items: [
      { i: 0, role: "user", row_id: 42, row_ids: [42], row_kind: "user", row_label: "USER · discord", len: 2, head: "hi" },
      { i: 1, role: "user", row_id: 42, row_ids: [42], item_kind: "internal", item_label: "INJECTED · turn_note", injection_kind: "turn_note", len: 12, head: "note" }] } });
  Object.assign(p.S, { sid: "s", gen: 1, mode: "wire", rows });
  const first = p.loadCompiled(); take(b.pending, /inspector\/compiled/).res(comp("h:two", false)); await first; await tick();
  const sel = b.root.querySelector(".mti-callsel");
  check(!b.root.querySelector(".mti-callnav").hidden && sel.options.length === 3, "call selector lists the session's calls");
  check(sel.options[2].textContent.includes("[review]") && !sel.options[2].textContent.endsWith("latest"), `a background review fork is badged, never the default (${sel.options[2].textContent})`);
  check(sel.options[1].textContent.startsWith("Call #2") && sel.options[1].textContent.endsWith("latest") && sel.value === "h:two",
        `latest call selected and labelled (${sel.options[1].textContent})`);
  check(!sel.options[0].textContent.includes("discord"), "the session's usual lane is not repeated on every call");
  check(b.root.querySelector('[data-ci="resp"]') && b.root.querySelector('[data-ci="resp"]').textContent.includes("MODEL OUTPUT"), "the call's response is its own item");
  sel.value = "h:one"; sel.dispatchEvent(new b.w.Event("change", { bubbles: true })); await tick();
  const older = take(b.pending, /inspector\/compiled\?.*call=h%3Aone/);
  check(!!older, "picking an older call requests exactly that call");
  if (older) older.res(comp("h:one", true));
  await tick();
  check(b.root.textContent.includes("1 newer rows not yet on the wire"), "freshness badge counts rows newer than the selected call");
  check(b.root.querySelector('[data-a="clatest"]'), "a historic call links back to the newest");
  check(b.root.querySelector('[data-a="clatest"]').matches("button.mt-link") && b.root.querySelector('[data-a="after"]').matches("button.mt-link"),
        "historic / newer-rows navigation is an inline link, its status a passive tag");
  check(!actingTags(b.w.document).length && !navNotLink(b.w.document).length, `Wire: no tag acts, every goto is a link (${actingTags(b.w.document)} ${navNotLink(b.w.document)})`);
  // back in Transcript, the +turn_note chip opens the first call that carried row 42, on its injection item
  p.S.comp = comp("h:two", false); p.S.wcall = null;
  b.root.querySelector('[data-mode="transcript"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  await tick();
  const fetched = take(b.pending, /inspector\/row\?id=/); if (fetched) fetched.res({ row: { id: 43, role: "assistant", content: "ok" }, class: {} });
  const chip = [...b.root.querySelectorAll('.mti-tl [data-a="towire"]')].find((x) => x.dataset.kind === "turn_note");
  check(!!chip, "transcript injection chip is a link to the wire");
  const wl = b.root.querySelector('.mti-tl [data-a="towire"][data-resp]');
  check(chip && chip.matches("button.mt-link") && /→/.test(chip.textContent) && wl && wl.matches("button.mt-link") && /^wire h:one/.test(wl.textContent.trim()),
        `Transcript: +turn_note and wire <call> are inline links with an arrow, not tags (${chip && chip.className} / ${wl && wl.className})`);
  check(!actingTags(b.w.document).length && !navNotLink(b.w.document).length, `Transcript: no tag acts (${actingTags(b.w.document)} ${navNotLink(b.w.document)})`);
  if (chip) chip.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  await tick();
  const jump = take(b.pending, /inspector\/compiled\?.*call=h%3Aone/);
  check(!!jump && p.S.mode === "wire", "the chip loads the call that first carried the row");
  if (jump) jump.res(comp("h:one", true));
  await tick();
  check(p.S.csel === "item:1", `the injection's own wire item is selected (got ${p.S.csel})`);
  // copy ref: the exact session, the call this snapshot came from, the item's position in that call, and its row
  let copied = null;
  b.w.document.execCommand = (cmd) => { const el = b.w.document.activeElement; copied = el.value.slice(el.selectionStart, el.selectionEnd); return cmd === "copy"; };
  Object.defineProperty(b.w, "isSecureContext", { value: false, configurable: true });
  const ref = b.w.document.querySelector(".mti-refv");
  check(ref && ref.textContent === "session=s call=h:one item=items[1] row=42", `wire ref names session, call, item in that call, row (${ref && ref.textContent})`);
  b.w.document.querySelector('[data-a="copyref"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  check(copied === "session=s call=h:one item=items[1] row=42", `copy ref puts exactly that on the clipboard (${copied})`);
  b.w.document.querySelector('[data-mode="transcript"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  await tick();
  p.S.sel = 0; b.w.document.querySelector('.mti-tl .mti-msg[data-i="0"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  await tick();
  check(ref.textContent === "session=s row=42", `transcript ref is the global row id, no call (${ref.textContent})`);
}

// 15. A session with only background-review captures: no default call, but the picker offers them and opens one.
{
  // Wire is the first and default mode; the two navigation tiers never share a label (mobile short labels).
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const modes = [...b.root.querySelectorAll(".mt-seg .mt-tab")].map((x) => x.dataset.mode + ":" + x.textContent);
  check(modes.join("|") === "wire:Wire|transcript:Transcript", `mode tabs are Wire | Transcript (${modes.join("|")})`);
  check(b.w.probeS.S.mode === "wire" && b.root.querySelector('.mt-seg .mt-tab[data-mode="wire"]').classList.contains("is-on"), "Wire is active by default");
  const src = readFileSync(bundle, "utf8"), views = /var VIEWS = (\[.*?\]\]);/.exec(src);
  const shorts = views ? JSON.parse(views[1]).map((v) => v[2]) : [];
  check(shorts.length === 2 && shorts.indexOf("Wire") < 0 && shorts.indexOf("Transcript") < 0, `top-level short labels do not repeat a mode name (${shorts})`);
}
{
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const p = b.w.probeS;
  Object.assign(p.S, { sid: "s", gen: 1, mode: "wire", rows: [] });
  const calls = [{ id: "h:rev", n: 1, started: 1e9, status: 200, model: "m", lane: "review", review: true }];
  const l = p.loadCompiled();
  take(b.pending, /inspector\/compiled/).res({ rev: "e", session: { id: "s" }, error: "no captured main request for this session — pick one of its 1 captured calls",
    calls, calls_total: 1, latest_call: null });
  await l; await tick();
  const sel = b.root.querySelector(".mti-callsel");
  check(!b.root.querySelector(".mti-callnav").hidden && sel.options[0].disabled && sel.value === "", `review-only session: picker visible with a placeholder (${sel.innerHTML})`);
  check(b.root.textContent.includes("Use the call picker above") && !b.root.textContent.includes("hermes plugins enable"), "no misleading 'enable the plugin' hint");
  sel.value = "h:rev"; sel.dispatchEvent(new b.w.Event("change", { bubbles: true })); await tick();
  check(!!take(b.pending, /inspector\/compiled\?.*call=h%3Arev/), "picking the review call requests it");
}

// 16. An assistant wire item with text and no tool calls prints its reply once (no flattened duplicate).
{
  const b = boot(true);
  b.api.mountInspector(b.root, {});
  const p = b.w.probeS;
  const reply = "You already did the steer part: those exact messages reached me mid-turn.";
  Object.assign(p.S, { sid: "s", gen: 1, mode: "wire", rows: [] });
  const l = p.loadCompiled();
  take(b.pending, /inspector\/compiled/).res({ rev: "a", call_id: "h:a", latest_call: "h:a", calls: [], session: { id: "s" }, system: {}, rows_after: [],
    wire: { which: "down", layer: "wire", meta: { status: 200 }, call: {}, keys: [], response: {}, items: [
      { i: 0, role: "assistant", row_id: 9, row_kind: "assistant", row_label: "ASSISTANT", len: reply.length, head: reply }] } });
  await l; await tick();
  b.root.querySelector('[data-ci="item:0"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const pt = take(b.pending, /wire\/part/);
  check(!take(b.pending, /wire\/readable/), "assistant items are not split into raw/wrapper runs");
  if (pt) pt.res({ type: "message", role: "assistant", content: [{ type: "output_text", text: reply }] });
  await tick();
  const n = b.w.document.querySelector(".mti-pane").textContent.split(reply).length - 1;
  check(n === 1, `assistant reply rendered exactly once in Wire › Readable (got ${n})`);
}

// 14. Wire JSON: the request tree opens along the path to the selected item, and collapsed objects say what they are.
{
  const { w, api } = boot();
  const req = { model: "m", tools: [{ type: "function", name: "read_file", description: "d", parameters: {} }, { type: "function", name: "terminal" }],
    input: Array.from({ length: 700 }, (_, i) => ({ role: i % 2 ? "assistant" : "user", content: "message " + i })) };
  const panel = api.jsonPanel("request", req, { open: 1, path: ["input", 650], targetOpen: 2 });
  w.document.body.appendChild(panel);
  const target = panel.querySelector(".mtj-target");
  check(target && target.open && target.textContent.includes("message 650"), "the path's item is rendered and open, even past the first 500 entries");
  const tools = [...panel.querySelectorAll("details")].find((d) => { const k = d.querySelector(":scope > summary > .mtj-k"); return k && k.textContent === '"tools"'; });
  check(tools && !tools.open, "values off the path stay collapsed");
  if (tools) { tools.open = true; tools.dispatchEvent(new w.Event("toggle")); }
  const t1 = tools && tools.querySelector(":scope > .mtj-ch > details:nth-of-type(2) > summary .mtj-label");
  check(t1 && t1.textContent === '"terminal"', `a collapsed tool shows its name (${t1 && t1.textContent})`);
  // JSON serialized inside a string: a passive "json in string" tag plus a labelled "show raw" action (the tag never acts)
  const sp = api.jsonPanel("request", { args: JSON.stringify({ path: "/x", n: 1 }) }, { open: 3 });
  w.document.body.appendChild(sp);
  const jt = sp.querySelector(".mtj-jstag"), jb = sp.querySelector("button.mtj-jstr");
  check(jt && jt.matches("span.mt-chip") && jb && jb.matches(".mt-btn") && jb.textContent === "show raw", "json-in-string: passive tag + labelled action");
  check(!actingTags(w.document).length, `JSON tree: no tag acts (${actingTags(w.document)})`);
  if (jb) jb.dispatchEvent(new w.MouseEvent("click", { bubbles: true }));
  check(!sp.querySelector(".mtj-jstag") && [...sp.querySelectorAll(".mtj-s")].some((x) => x.textContent.includes("path")), "show raw swaps in the raw string");
}

// 8. Session picker: useful titles/depth, no capability-role badges, and last-query-wins metadata search.
{
  const b = boot(true);
  b.api.mountInspector(b.root, {}); await tick();
  const initial = take(b.pending, /inspector\/sessions/);
  initial.res({ main: null, sessions: [
    { id: "child", source: "subagent", role: "orchestrator", title: 'Subagent: <latest_user_message sent_at="…',
      display_title: "Subagent: Audit serving credentials", model: "gpt-6.1-sol", message_count: 4,
      lineage: { kind: "delegate", depth: 1 } },
    { id: "leaf", source: "subagent", role: "leaf", title: "Subagent:", message_count: 2,
      lineage: { kind: "delegate", depth: 2 } }
  ] });
  await tick();
  const list = b.w.document.querySelector('.mti-slist');
  const names = [...list.querySelectorAll('.mti-st')].map((x) => x.textContent);
  check(names.join("|") === "Audit serving credentials|leaf",
        `child sessions show their assignment / id without repeating the subagent badge, never an empty colon (${names.join("|")})`);
  check(!list.textContent.includes("Subagent:") && !list.textContent.includes("Subagent ·") && list.textContent.includes("subagent"),
        "the 'Subagent' prefix is gone from names while the subagent tag remains");
  check(list.querySelector('.mti-ses[data-id="leaf"] .mti-st').title === "Subagent:", "the stored title stays available as the tooltip");
  check(list.textContent.includes("delegate · d1") && list.textContent.includes("delegate · d2"), "useful lineage chips remain");
  check(![...list.querySelectorAll('.mt-chip')].some(x => /^(orchestrator|leaf)$/.test(x.textContent)), "capability-role chips removed");
  const input = b.w.document.querySelector('.mti-sq');
  input.value = "sol subagent"; input.dispatchEvent(new b.w.Event("input"));
  await new Promise(r => setTimeout(r, 270));
  const a = take(b.pending, /inspector\/sessions.*q=sol%20subagent/);
  input.value = "argon d1"; input.dispatchEvent(new b.w.Event("input"));
  await new Promise(r => setTimeout(r, 270));
  const fresh = take(b.pending, /inspector\/sessions.*q=argon%20d1/);
  check(!!a && !!fresh, "multi-token metadata searches are sent intact to the server, not filtered locally");
  fresh.res({ main: null, sessions: [{ id: "argon-child", display_title: "Argon result", source: "subagent", model: "gemini-4-argon" }] });
  await tick();
  a.res({ main: null, sessions: [{ id: "stale-sol", title: "Stale search", source: "subagent" }] });
  await tick();
  check(list.textContent.includes("Argon result") && !list.textContent.includes("Stale search"), "old picker results cannot overwrite the new query");
}

// 9. Inspector gauges follow deep links and picker switches; a late old session cannot overwrite one.
{
  const b = boot(true), chosen = [];
  b.api.mountInspector(b.root, { session: "child", mode: "transcript", onSessionSelected: id => chosen.push(id) });
  take(b.pending, /inspector\/sessions/).res({ main: "bot", sessions: [
    { id: "bot", title: "Bot Chat", main: true, source: "discord" },
    { id: "child", title: "Child task", source: "subagent", parent_session_id: "bot" },
    { id: "other", title: "Other chat", source: "cli" }
  ] }); await tick();
  const doc = (id, title, window, prompt) => ({ session: { id, title }, rows: [], total: 0, matched_calls: 0,
    context: { id, title, ctx_window: window, last_prompt_tokens: prompt, message_count: 7, compressor_trigger: window / 2 } });
  take(b.pending, /inspector\/session\?id=child/).res(doc("child", "Child task", 1000, 100)); await tick();
  const gauge = b.root.querySelector('.mti-gauge');
  check(gauge.textContent.includes("Child task") && gauge.textContent.includes("1,000"), "deep-linked child has its own context gauge");
  b.w.document.querySelector('[data-id="other"]').click(); await tick();
  const stale = take(b.pending, /inspector\/session\?id=other/);
  b.w.document.querySelector('[data-id="child"]').click(); await tick();
  take(b.pending, /inspector\/session\?id=child/).res(doc("child", "New child context", 2000, 300)); await tick();
  stale.res(doc("other", "Stale other context", 9000, 8000)); await tick();
  check(gauge.textContent.includes("New child context") && !gauge.textContent.includes("Stale other"), "stale session response cannot overwrite selected gauge");
  check(chosen.join(',') === "child,other,child", "selection callback survives picker changes for cross-view state");
}

// 10. With no Bot Chat, choose a recent root without starring it.
{
  const b = boot(true);
  b.api.mountInspector(b.root, { mode: "transcript" });
  take(b.pending, /inspector\/sessions/).res({ main: null, sessions: [
    { id: "recent", title: "Recent CLI", source: "cli" }, { id: "older", source: "discord" }
  ] }); await tick();
  check(!!take(b.pending, /inspector\/session\?id=recent/), "no canonical Bot Chat: initial selection uses recent root");
  check(!b.w.document.querySelector('.mti-slist').textContent.includes("★"), "recent root is not falsely starred main");
}

// 11. Calls & Cache uses the remembered/filtered selection, never the Bot Chat's gauge.
{
  const b = boot(true);
  b.api.mountTelemetry(b.root, { session: "child" });
  take(b.pending, /\/calls\?/).res(callsPayload("gauge", 1)); await tick();
  take(b.pending, /\/sessions\?/).res({ main: { id: "bot", ctx_window: 999999 }, sessions: [] }); await tick();
  const stale = take(b.pending, /inspector\/session\?id=child/);
  check(!!stale, "Calls view requests remembered selected child, not main Bot Chat");
  b.root.querySelector('[data-c="sess"]').value = "other";
  const update = b.w.probeT.load();
  take(b.pending, /\/calls\?/).res(callsPayload("gauge-other", 1)); await update; await tick();
  take(b.pending, /inspector\/session\?id=other/).res({ context: { id: "other", title: "Selected other", ctx_window: 4000, last_prompt_tokens: 800, message_count: 9 } }); await tick();
  stale.res({ context: { id: "child", title: "Stale child", ctx_window: 1000, last_prompt_tokens: 100 } }); await tick();
  const gauge = b.root.querySelector('.mtt-gauge');
  check(gauge.textContent.includes("Selected other") && gauge.textContent.includes("4,000") && !gauge.textContent.includes("Stale child"),
        "Calls gauge follows filter selection with generation safety");
}

// 12. Expanded miss cards show the bounded change, escape its content, and
// keep transport/event boilerplate collapsed rather than above the evidence.
{
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const data = callsPayload("diff", 1);
  const side = (prefix, change, suffix) => ({ prefix, change, suffix, omitted_prefix: 320, omitted_change: 0, omitted_suffix: 0 });
  data.rows[0].diverge = JSON.stringify({why:"tool declarations changed", at:1, role:"tools", prev_len:579, cur_len:611,
    common_items:1, items:11, change:{v:2,path:"tools[0].description",offset:380,line:1,
    before:side("Read sample file", "", ""),after:side("Read sample file", " <img src=x onerror=alert(1)>", ""),summary:""}});
  data.rows[0].events = [{ts:1,kind:"debug",detail:"Verbose transport event"}];
  take(b.pending,/\/calls\?/).res(data); await tick();
  take(b.pending,/\/sessions\?/).res({main:null,sessions:[]}); await tick();
  b.root.querySelector('tr[data-id]').dispatchEvent(new b.w.MouseEvent("click",{bubbles:true})); await tick();
  const card=b.root.querySelector('.mtt-det');
  check(!!card.querySelector('.mtt-diff .is-del') && !!card.querySelector('.mtt-diff .is-add'), "real expanded card renders deletion/addition rows");
  check(card.querySelector('mark').textContent.includes('<img'), "only the changed span is highlighted as literal text");
  check(!card.querySelector('img'), "diff contents cannot inject markup");
  check(card.querySelector('.mtt-diff-path').textContent.includes('tools[0].description'), "diff identifies exact changed field");
  check(!card.querySelector('.mtt-transport').open, "transport and events start collapsed");
  check(!card.querySelector('.mtt-miss').textContent.includes('prev:'), "obsolete identical-prefix dump is absent");
  check(!card.querySelector('.mtt-miss').textContent.includes('tool declarations changed') &&
        b.root.querySelector('tr[data-id] .mtt-whycell').textContent === 'tool declarations changed',
        "the miss reason is printed once, on the row — the drawer only adds the evidence");
  check(!card.querySelector('.mtt-diff code') && card.querySelectorAll('.mtt-diff-code').length === 2,
        "diff lines are not <code> (host code styles would resize them)");
}

// 17. General call errors: failed (transport sentinel, 429, 503) vs recovered vs no status vs an SDK code; 429 count kept;
//     the error filter asks the server for errors=1 and narrows to one outcome; no error text reaches the summary.
{
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const sum = (status, nfail) => {  // what the backend's error_summary (v1) sends
    const st = typeof status === "number" ? status : null, failed = st != null && !(st >= 200 && st < 300), ok = st != null && st >= 200 && st < 300;
    return { v: 1, scope: "call", outcome: failed ? "failed" : ok ? "succeeded" : "unknown",
      category: !failed ? null : st === 0 ? "transport_or_invalid_response" : st === 429 ? "rate_limit" : st >= 500 ? "server" : "http",
      affected: failed || nfail > 0, recovered: ok && nfail > 0, recorded_failure_observations: nfail };
  };
  const data = callsPayload("err", 7);
  const set = [["timeout", 0, 1, 0], ["rl", 429, 2, 2], ["srv", 503, 1, 0], ["rec", 200, 2, 1], ["pending", null, null, 0], ["sdk", "insufficient_quota", null, 0], ["ok", 201, 0, 0]];
  set.forEach(([id, st, nf, n429], i) => Object.assign(data.rows[i], { id, status: st, nfail: nf, n429, events: [{ ts: 1, kind: "error", detail: "Bearer sk-SECRET provider said no" }], error_summary: sum(st, nf) }));
  delete data.rows[6].error_summary;  // an older backend without summaries: same rules from status/nfail
  take(b.pending, /\/calls\?/).res(data); await tick();
  take(b.pending, /\/sessions\?/).res({ main: null, sessions: [] }); await tick();
  const cell = (id) => { const r = b.root.querySelector(`tr[data-id="${id}"]`); return r && [...r.children][COLIDX("errors")].textContent; };
  function COLIDX(name) { return [...b.root.querySelectorAll(".mtt-calls thead th")].findIndex((th) => th.textContent === name); }
  check(cell("timeout") === "failed · transport / invalid response", `status 0 is a failed transport call (${cell("timeout")})`);
  check(cell("rl") === "failed · rate limit 429" && COLIDX("429") < 0, "a final 429 is a failed rate-limit call; no separate 429 column");
  check(cell("srv") === "failed · server 503", `5xx is a server failure (${cell("srv")})`);
  check(cell("rec") === "recovered · 2 obs · 429" && !b.root.querySelector('tr[data-id="rec"]').classList.contains("is-err"),
        `one call, several failed attempts (a 429 among them), then success: recovered, not failed, the rate limit noted (${cell("rec")})`);
  check(cell("pending") === "no status" && !b.root.querySelector('tr[data-id="pending"]').classList.contains("is-err"), "no status is unknown, not an error");
  check(cell("sdk") === "code insufficient_quota", `an SDK code is shown as an unknown-outcome code (${cell("sdk")})`);
  check(cell("ok") === "·", "a 2xx with no failures shows nothing");
  b.root.querySelector('tr[data-id="rec"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const es = b.root.querySelector(".mtt-errsum");
  check(es && /failure observations 2 \(stored events, not deduplicated attempts\)/.test(es.textContent) && es.textContent.includes("not a conversation turn"),
        `detail states the observation semantics and call scope (${es && es.textContent})`);
  check(!b.root.querySelector(".mtt-errsum, .mtt-err") || ![...b.root.querySelectorAll(".mtt-errsum, .mtt-err")].some((x) => /SECRET|said no/.test(x.textContent + x.title)), "no error text in the error summary");
  const sel = b.root.querySelector('[data-c="errs"]');
  sel.value = "failed"; sel.dispatchEvent(new b.w.Event("change", { bubbles: true })); await tick();
  const req = take(b.pending, /\/calls\?/);
  check(req && /errors=1/.test(req.url), "the error filter asks the server for errors=1 (pending/unknown rows excluded server-side)");
  const aff = callsPayload("err2", 4); [set[0], set[1], set[2], set[3]].forEach(([id, st, nf, n429], i) => Object.assign(aff.rows[i], { id, status: st, nfail: nf, n429, error_summary: sum(st, nf) }));
  if (req) req.res(aff); await tick();
  const shown = [...b.root.querySelectorAll(".mtt-calls tbody tr[data-id]")].map((r) => r.dataset.id).join(",");
  check(shown === "timeout,rl,srv", `failed calls only (${shown})`);
  sel.value = "recovered"; sel.dispatchEvent(new b.w.Event("change", { bubbles: true })); await tick();
  const req2 = take(b.pending, /\/calls\?/); if (req2) req2.res(aff); await tick();
  const shown2 = [...b.root.querySelectorAll(".mtt-calls tbody tr[data-id]")].map((r) => r.dataset.id).join(",");
  check(shown2 === "rec", `recovered calls only (${shown2})`);
}

// 18. Overview: family cards group errors (failed / recovered / no status) with 429s as a subtype; the key card labels
//     the proxy's failed upstream attempts (any status) with their 429 subset, plus per-key failed/recovered calls.
{
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const data = callsPayload("ov", 2);
  data.summary = { claude: { n: 9, p: 1, c: 1, o: 0, t: 0, cost: 0, eq: 0, miss: 0, n429: 3, retry: 4, err: 2, empty: 0,
    failed_calls: 2, affected_calls: 4, recovered_calls: 2, unknown_calls: 1, recorded_failure_observations: 6 } };
  // one credential in two call-scope groups (another provider/project) + a distinct credential; proxy evidence is per key
  data.keys = [{ family: "claude", auth_key: "abcd", auth_type: "oauth", n: 9, n429: 3, failed_calls: 2, recovered_calls: 2, avg_s: 1, avg_hit: 90 },
    { family: "claude", provider: "other-route", project: "p2", auth_key: "abcd", auth_type: "oauth", n: 4, n429: 0, failed_calls: 1, recovered_calls: 0, avg_s: 1, avg_hit: 90 },
    { family: "claude", auth_key: "wxyz", auth_type: "api", n: 3, n429: 0, failed_calls: 0, recovered_calls: 1, avg_s: 1, avg_hit: 90 }];
  data.fail_keys = [{ key: "abcd", n: 5, n429: 3, last: 1e9 }, { key: "wxyz", n: 2, n429: 0, last: 1e9 }, { key: "zzzz", n: 9, n429: 9, last: 1e9 }];
  take(b.pending, /\/calls\?/).res(data); await tick();
  take(b.pending, /\/sessions\?/).res({ main: null, sessions: [] }); await tick();
  const grp = b.root.querySelector(".mtt-strip .mtt-errgrp");
  check(grp && grp.textContent.replace(/\s+/g, " ").trim() === "errors failed 2 recovered 2 no status 1 · 429s 3 retry 4.00s",
        `family card: one errors group with 429s as its subtype (${grp && grp.textContent})`);
  const card = b.root.querySelector(".mtt-strip .mt-card");
  check(card && !/(^|\s)429 \d/.test(card.querySelector(".mtt-ckv").textContent.replace(grp.textContent, "")), "no separate top-level 429 figure outside the errors group");
  const keyTable = b.root.querySelector(".mtt-strip .mtt-wide > .mtt-scroll table");
  const heads = [...keyTable.querySelectorAll("th")].map((x) => x.textContent);
  check(heads.join("|") === "family|key|scope|calls|avg s|avg hit|failed|recovered", `key card columns are call outcomes only (${heads.join("|")})`);
  const krows = [...keyTable.querySelectorAll("tbody tr")].map((tr) => [...tr.children].slice(6, 8).map((x) => x.textContent).join(","));
  check(krows.join(" ") === "2,2 1,0 0,1", `key card: failed / recovered calls per call-scope group (${krows.join(" ")})`);
  const att = b.root.querySelector(".mtt-strip details.mtt-attempts");
  check(att && !att.open && /· 7 failed \(retries included; attempts, not calls\)/.test(att.querySelector("summary").textContent),
        `attempts counted once per credential, never per call-scope group, only for keys in view (${att && att.querySelector("summary").textContent})`);
  const ah = att && [...att.querySelectorAll("th")].map((x) => x.textContent).join("|");
  const arows = att ? [...att.querySelectorAll("tbody tr")].map((tr) => [...tr.children].slice(1, 3).map((x) => x.textContent).join(",")) : [];
  check(ah === "key|failed attempts|of which 429|last" && arows.join(" ") === "5,3 2,0",
        `attempt detail: one row per credential with its 429 subset; the shared key is not repeated (${ah} / ${arows.join(" ")})`);
  check(arows.reduce((n, r) => n + +r.split(",")[0], 0) === 7, "the summary total equals the visible attempt rows");
}

// 19. Family tabs: every family gets a tab (no top-4 cap, no "Other" bucket), All and Sessions pinned around a strip,
//     and the order holds still across polls where counts cross; newcomers are appended. A new window re-sorts.
try {
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const fams = (list) => list.map(([family, n]) => ({ family, label: family.toUpperCase(), n }));
  const order = () => [...b.root.querySelectorAll(".mtt-tabs .mt-tab[data-t]")].map((x) => x.dataset.t).join(",");
  const d1 = callsPayload("t1", 2); d1.families = fams([["a", 10], ["b", 9], ["c", 8], ["d", 7], ["e", 6], ["f", 5], ["g", 4], ["h", 3]]);
  take(b.pending, /\/calls\?/).res(d1); await tick();
  const s = take(b.pending, /\/sessions\?/); if (s) s.res({ main: null, sessions: [] }); await tick();
  check(order() === "all,a,b,c,d,e,f,g,h,sessions", `every family has a tab, no cap or Other bucket (${order()})`);
  const strip = b.root.querySelector(".mtt-fstrip"), pins = [...b.root.querySelectorAll(".mtt-pin")].map((x) => x.dataset.t);
  check(strip && strip.querySelectorAll(".mt-tab").length === 8 && pins.join(",") === "all,sessions" && !strip.querySelector('[data-t="all"], [data-t="sessions"]'),
        "families scroll in a strip; All and Sessions sit outside it (pinned)");
  check(b.root.querySelector('.mtt-tablist[role="tablist"]') && !b.root.innerHTML.includes(">Other<"), "one tablist; no aggregate Other tab");
  const d2 = callsPayload("t2", 2); d2.families = fams([["h", 30], ["g", 20], ["a", 10], ["b", 9], ["c", 8], ["d", 7], ["e", 6], ["f", 5], ["i", 1]]);
  b.w.probeT.load(true); await tick(); take(b.pending, /\/calls\?/).res(d2); await tick();
  check(order() === "all,a,b,c,d,e,f,g,h,i,sessions", `a poll whose counts cross keeps the order and appends the newcomer (${order()})`);
  b.root.querySelector('.mtt-fstrip [data-t="c"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const req = take(b.pending, /\/calls\?/);
  check(req && /family=c(&|$)/.test(req.url), "a family tab asks for that family only");
  const d3 = callsPayload("t3", 1); d3.families = fams([["h", 30], ["a", 10]]);
  if (req) req.res(d3); await tick();
  check(order() === "all,a,c,h,sessions", `families that leave are dropped, the selected one keeps its tab (${order()})`);
  const on = [...b.root.querySelectorAll(".mtt-tabs .mt-tab[aria-selected='true']")].map((x) => x.dataset.t);
  const focusable = [...b.root.querySelectorAll(".mtt-tabs .mt-tab")].filter((x) => x.tabIndex === 0).map((x) => x.dataset.t);
  check(on.join() === "c" && focusable.join() === "c", `roving tabindex: only the selected tab is in the tab order (${on} / ${focusable})`);
  const tc = b.root.querySelector('.mtt-fstrip [data-t="c"]'); tc.focus();
  tc.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  check(b.w.document.activeElement && b.w.document.activeElement.dataset.t === "h", "→ moves focus to the next tab");
  b.w.document.activeElement.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "End", bubbles: true }));
  check(b.w.document.activeElement.dataset.t === "sessions", "End reaches the pinned Sessions tab");
  const hours = b.root.querySelector('[data-c="hours"]'); hours.value = "24"; hours.dispatchEvent(new b.w.Event("change", { bubbles: true })); await tick();
  const d4 = callsPayload("t4", 1); d4.families = fams([["h", 30], ["g", 20], ["a", 10]]);
  take(b.pending, /\/calls\?/).res(d4); await tick();
  check(order() === "all,h,g,a,c,sessions", `a new window re-sorts by count (selected c kept) (${order()})`);
  check(!b.root.querySelector(".mti-fbtn, .mti-fcount") && !b.w.document.querySelector('[data-a="fpanel"]'), "no generic filters button: every filter is its own visible control");
  const ccopy = [...b.w.document.querySelectorAll(".mtt-filters, #mtt-fhelp, .mtt-stamp")].map((x) => x.textContent).join(" ") +
    [...b.root.querySelectorAll(".mtt-tabs [title]")].map((x) => x.title).join(" ");
  check(!/ · /.test(ccopy), `Calls toolbar, help, stamp and tab tooltips carry no dot-joined copy (${(ccopy.match(/.{12} · .{12}/) || [""])[0]})`);
  // family tabs are the only model/route filter (no competing provider select); freshness lives in the page header
  check(!b.root.querySelector('[data-c="prov"]') && !/provider/i.test(b.root.querySelector(".mtt-filters").textContent), "no provider select competing with the family tabs");
  check(b.root.querySelector(".mtt-stamp").textContent === "", `no duplicate freshness line under the tabs (${b.root.querySelector(".mtt-stamp").textContent})`);
  const th = b.root.querySelector('.mtt-calls th[data-sort="errors"]');
  check(th && /Sorts failed first/.test(th.title), "the errors column sorts, and says how");
  if (th) th.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const sreq = take(b.pending, /\/calls\?/);
  check(sreq && /sort=errors/.test(sreq.url), "sorting by errors asks the server for sort=errors");
  check(!b.root.querySelector('option[value="n429"]'), "no orphaned 429s sort key");
  check(!actingTags(b.w.document).length, `Calls: no tag acts (${actingTags(b.w.document)})`);
} catch (e) { check(false, `19 (family tabs) threw: ${e.message}`); }

// 20. Inspector toolbar: labelled groups (rows = a choice, include = toggles), refresh as a switch; help is an anchored
//     popover outside the page flow, Esc closes it and returns focus; f flips the rows choice; the filters count follows.
try {
  const b = boot(true);
  b.api.mountInspector(b.root, { session: "s", mode: "transcript" });
  await tick();
  const bar = b.root.querySelector('.mti-filters[role="toolbar"]');
  check(bar && bar.firstElementChild.classList.contains("mti-q"), "search leads the toolbar");
  const labels = [...bar.querySelectorAll(".mt-segb, .mt-tog, .mt-switch")].map((x) => x.textContent.trim()).join("|");
  check(labels === "all|⚠ flagged|tool messages|pre-compaction|auto-refresh", `filter names and meanings kept (${labels})`);
  check(bar.querySelector('[role="radiogroup"] input[type="radio"][data-f="flag"]') && bar.querySelector('input[role="switch"][data-f="live"]'),
        "rows is a radio choice; auto-refresh is a switch");
  const help = b.root.querySelector(".mti-help"), pop = b.w.document.getElementById("mti-fhelp");
  check(pop && !b.root.contains(pop) && pop.hidden && help.getAttribute("aria-controls") === "mti-fhelp", "help lives in the overlay layer, hidden");
  help.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  check(!pop.hidden && help.getAttribute("aria-expanded") === "true" && pop.querySelectorAll("dt").length === 5, "? opens a definition list");
  b.w.document.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  check(pop.hidden && help.getAttribute("aria-expanded") === "false" && b.w.document.activeElement === help, "Esc closes help and returns focus to ?");
  help.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  b.w.document.body.dispatchEvent(new b.w.MouseEvent("pointerdown", { bubbles: true }));
  check(pop.hidden, "a press outside closes help");
  b.w.document.body.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "f", bubbles: true }));
  check(b.root.querySelector('[data-f="flag"]').checked && !b.root.querySelector('[data-rows="all"]').checked, "f selects ⚠ flagged");
  b.w.document.body.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "f", bubbles: true }));
  check(b.root.querySelector('[data-rows="all"]').checked, "f again returns to all");
  // the help popover closes when the view it explains changes (mode switch) and when the view is unmounted
  help.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
  check(!pop.hidden, "help reopens");
  b.root.querySelector('[data-mode="wire"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  check(pop.hidden && help.getAttribute("aria-expanded") === "false", "switching Wire / Transcript closes help");
  const copy = [...b.w.document.querySelectorAll(".mti-filters, #mti-fhelp")].map((x) => x.textContent).join(" ");
  check(!/ · /.test(copy), `no dot-joined copy in the toolbar or its help (${(copy.match(/.{12} · .{12}/) || [""])[0]})`);
} catch (e) { check(false, `20 (inspector toolbar) threw: ${e.message}`); }

// 21. Auto-refresh badge is honest: off when switched off, paused while reading (an expanded call), live otherwise.
try {
  const b = boot();
  b.api.mountTelemetry(b.root);
  await tick();
  take(b.pending, /\/calls\?/).res(callsPayload("lv", 3)); await tick();
  const s = take(b.pending, /\/sessions\?/); if (s) s.res({ main: null, sessions: [] }); await tick();
  const frame = () => new Promise((r) => setTimeout(r, 40));
  const badge = () => b.root.querySelector(".mt-live").textContent;
  await frame();
  check(badge() === "" && b.root.querySelector(".mt-live").dataset.liveState === "live", `refreshing: no status text (${badge()})`);
  const sw = b.root.querySelector('[data-c="auto"]'); sw.checked = false; sw.dispatchEvent(new b.w.Event("change", { bubbles: true })); await frame();
  check(badge() === "" && sw.getAttribute("role") === "switch" && !sw.checked, `switched off: the switch says it, no extra text (${badge()})`);
  sw.checked = true; sw.dispatchEvent(new b.w.Event("change", { bubbles: true }));
  b.root.querySelector(".mtt-calls tbody tr[data-id]").dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await frame();
  const st = b.root.querySelector(".mt-live");
  check(badge() === "paused" && /New calls wait/.test(st.title) && sw.getAttribute("aria-describedby") === st.id, `on but holding: one word, the reason in its tooltip and description (${badge()})`);
} catch (e) { check(false, `21 (auto-refresh badge) threw: ${e.message}`); }

// 22. Passive badges never filter (review P2): clicking the refresh-status badge in any state leaves the session and
//     family filters alone and issues no request; a real session link (positive control) still filters. A poll that
//     changes a family's count keeps keyboard focus on that family's tab (review P3).
try {
  const b = boot();
  b.api.mountTelemetry(b.root);
  await tick();
  const d0 = callsPayload("pb", 3); d0.families = [{ family: "claude", label: "Claude", n: 3 }, { family: "gpt", label: "GPT", n: 2 }];
  take(b.pending, /\/calls\?/).res(d0); await tick();
  const s0 = take(b.pending, /\/sessions\?/); if (s0) s0.res({ main: null, sessions: [{ id: "sess-1", title: "one", source: "cli" }] }); await tick();
  b.pending.splice(0);
  const frame = () => new Promise((r) => setTimeout(r, 40));
  const badge = b.root.querySelector(".mt-live"), sess = b.root.querySelector('[data-c="sess"]');
  b.root.querySelector('.mtt-fstrip [data-t="gpt"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const g = take(b.pending, /\/calls\?/); if (g) g.res(Object.assign(callsPayload("pb2", 2), { families: d0.families })); await tick();
  b.pending.splice(0);
  const sw = b.root.querySelector('[data-c="auto"]');
  for (const st of ["live", "off", "reading"]) {
    if (st === "off") { sw.checked = false; sw.dispatchEvent(new b.w.Event("change", { bubbles: true })); }
    if (st === "reading") { sw.checked = true; sw.dispatchEvent(new b.w.Event("change", { bubbles: true }));
      b.root.querySelector(".mtt-calls tbody tr[data-id]").dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); }
    await frame(); b.pending.splice(0);
    badge.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true }));
    badge.dispatchEvent(new b.w.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await tick();
    const sel = b.root.querySelector(".mtt-tabs .mt-tab.is-on");
    check(sess.value === "" && sel && sel.dataset.t === "gpt" && !b.pending.some((p) => /\/calls\?/.test(p.url)),
          `badge "${badge.textContent}" click/Enter changed nothing (session="${sess.value}", tab=${sel && sel.dataset.t}, requests=${b.pending.map((p) => p.url)})`);
  }
  check(!badge.hasAttribute("data-s") && badge.dataset.liveState, "the badge's state is its own attribute, not a session-link marker");
  // positive control: a real session link filters to that session
  b.root.querySelector('.mtt-pin[data-t="sessions"]').dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  const ss = take(b.pending, /\/sessions\?/); if (ss) ss.res({ main: null, sessions: [{ id: "sess-1", title: "one", source: "cli", api_call_count: 1 }] });
  const sc = take(b.pending, /\/calls\?/); if (sc) sc.res(Object.assign(callsPayload("pb3", 1), { families: d0.families })); await tick();
  const link = b.root.querySelector('[data-session-link="sess-1"]');
  check(link && link.matches("button.mt-link"), "a session in the Sessions view is an inline session link");
  b.pending.splice(0);
  if (link) link.dispatchEvent(new b.w.MouseEvent("click", { bubbles: true })); await tick();
  check(sess.value === "sess-1" && b.pending.some((p) => /\/calls\?.*session=sess-1/.test(p.url)), `a session link filters to its session (${sess.value})`);
  b.pending.splice(0);
} catch (e) { check(false, `22 (passive badge / session link) threw: ${e.message}`); }
try {
  const b = boot(true);
  b.api.mountTelemetry(b.root);
  const fam = (n) => [{ family: "claude", label: "Claude", n }, { family: "gpt", label: "GPT", n: 2 }];
  const d0 = callsPayload("fc", 2); d0.families = fam(3);
  take(b.pending, /\/calls\?/).res(d0); await tick();
  const s = take(b.pending, /\/sessions\?/); if (s) s.res({ main: null, sessions: [] }); await tick();
  b.root.querySelector('.mtt-fstrip [data-t="claude"]').focus();
  check(b.w.document.activeElement.dataset.t === "claude", "precondition: the claude tab has focus");
  const d1 = callsPayload("fc2", 2); d1.families = fam(4);
  b.w.probeT.load(true); await tick(); take(b.pending, /\/calls\?/).res(d1); await tick();
  const t = b.root.querySelector('.mtt-fstrip [data-t="claude"]');
  check(/4 calls/.test(t.title) && b.w.document.activeElement === t, `focus stays on the family tab across a poll that changed its count (${b.w.document.activeElement.tagName} ${b.w.document.activeElement.dataset && b.w.document.activeElement.dataset.t})`);
} catch (e) { check(false, `22b (tab focus across polls) threw: ${e.message}`); }

// the mounted views keep interval timers: exit explicitly
if (fails.length) { console.log("FAIL\n" + fails.join("\n")); process.exit(1); }
console.log("ok: calls race, stale older page, part-cache key, copy without download, part cache per view revision, sessions race, wire readable runs, call history + transcript jumps, wire JSON path");
process.exit(0);
