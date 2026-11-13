(function () {
  "use strict";
  // Wiretap · Wire & Cache Inspector — the wiretap plugin's dashboard tab (Session & Wire Inspector + Call Telemetry).
  // Injectable renderer shared with the native Desktop entry (no iframes): the React tab owns a container,
  // and each view mounts vanilla DOM into it (scoped CSS in style.css, full cleanup on unmount).
  // Backend: dashboard/plugin_api.py at /api/plugins/wiretap/ (read-only over the plugin's capture store).
  // BEGIN SHARED WIRETAP RENDERER — desktop/build.py bundles this factory without evaluating source.
  function createWiretapUI(SDK) {
  var React = SDK.React;
  var h = React.createElement;
  var useState = SDK.hooks.useState;
  var useEffect = SDK.hooks.useEffect;
  var useRef = SDK.hooks.useRef;

  var NAME = "wiretap";
  var API = "/api/plugins/" + NAME;
  var MOBILE_Q = "(max-width: 768px)";
  var WIDE_Q = "(min-width: 1400px)";

  // ───────────────────────── shared helpers ─────────────────────────
  function api(path) { return SDK.fetchJSON(API + path); }
  // A wire-part request's URL (call, layer, every argument) and its cache key: the URL plus the revision of the view
  // it was read for — the same call's stored request changes when the exact wire lands after adapter input.
  function partQuery(callId, which, q) { return "id=" + encodeURIComponent(callId) + "&which=" + which + "&" + q; }
  function partKey(callId, which, q, rev) { return (rev || "") + "|" + partQuery(callId, which, q); }
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  };
  var num = function (x) { return x == null ? "—" : Number(x).toLocaleString(); };
  var fmtT = function (ts) {
    return ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
  };
  var shortT = function (ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    var t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return d.toDateString() === new Date().toDateString() ? t : (d.getMonth() + 1) + "/" + d.getDate() + " " + t;
  };
  var ago = function (ts) {
    if (!ts) return "";
    var s = Date.now() / 1000 - ts;
    return s < 90 ? Math.round(s) + "s" : s < 5400 ? Math.round(s / 60) + "m" : s < 172800 ? Math.round(s / 3600) + "h" : Math.round(s / 86400) + "d";
  };
  var mm = function (q) { return window.matchMedia(q).matches; };
  function store(k, v) {
    try {
      if (SDK.storage) {
        if (v === undefined) return SDK.storage.get(k, null);
        SDK.storage.set(k, v);
        return null;
      }
      if (v === undefined) { var x = window.localStorage.getItem("wiretap:" + k); return x == null ? null : JSON.parse(x); }
      window.localStorage.setItem("wiretap:" + k, JSON.stringify(v));
    } catch (e) { return null; }
    return null;
  }
  function typing(e) {
    var t = e.target;
    return t && (t.tagName === "INPUT" && t.type !== "checkbox" && t.type !== "radio" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
  }
  // Enter / Space on a focused control belong to that control, not to a view shortcut
  function onControl(e) { return !!(e.target && e.target.closest && e.target.closest("button, a, summary, label, [role=tab], [role=switch]")); }

  // ── shared toolbar pieces (Inspector and Calls use the same grammar) ──
  function helpRow(term, def, key) {
    return "<div><dt>" + esc(term) + (key ? ' <kbd>' + esc(key) + "</kbd>" : "") + "</dt><dd>" + esc(def) + "</dd></div>";
  }
  function helpBtnHTML(id) {
    return '<button type="button" class="mt-btn mti-help" data-a="fhelp" aria-expanded="false" aria-controls="' + id + '" aria-haspopup="dialog" ' +
      'aria-label="What these controls do" title="What these controls do">?</button>';
  }
  // Auto-refresh is behaviour, not a filter: a switch. When it is on but not refreshing, one word says so ("paused");
  // the reason is its tooltip and accessible description, not more visible text.
  function liveHTML(attr, key, tip, id) {
    return '<div class="mt-livebox"><label class="mt-switch" title="' + esc(tip) + '"><input type="checkbox" role="switch" data-' + attr + '="' + key + '" checked aria-describedby="' + id + '">' +
      '<span class="mt-swt" aria-hidden="true"></span><span class="mt-swl">auto-refresh</span></label>' +
      '<span class="mt-live is-on" id="' + id + '" data-live-state="live" role="status"></span></div>';
  }
  var LIVE = {
    live: ["", "on", "Refreshing"],
    off: ["", "off", "Auto-refresh is off. Press r to refresh."],
    scrolled: ["paused", "paused", "Paused until you scroll back to the latest item."],
    detail: ["paused", "paused", "Paused while the detail sheet is open."],
    reading: ["paused", "paused", "Paused while a call is open or the list is scrolled. New calls wait behind the refresh button; press r to show them."],
  };
  function setLive(el, state) {
    var v = LIVE[state] || LIVE.live;
    if (!el || el.dataset.liveState === state) return;
    el.dataset.liveState = state; el.textContent = v[0]; el.className = "mt-live is-" + v[1]; el.title = v[2];
  }
  // Anchored popover (help; the phone filter panel): lives in the overlay layer at a fixed position under its trigger,
  // never in the page flow, so opening it cannot move anything. Esc or a press outside closes it; Esc returns focus.
  function anchoredPop(trigger, pop, onToggle) {
    var open = false;
    function pos() {
      if (!open) return;
      var r = trigger.getBoundingClientRect(), vw = document.documentElement.clientWidth || window.innerWidth, vh = window.innerHeight;
      var w = Math.min(pop.offsetWidth || 320, vw - 16), left = Math.min(Math.max(8, r.right - w), vw - w - 8);
      pop.style.left = Math.round(left) + "px"; pop.style.top = Math.round(r.bottom + 6) + "px";
      pop.style.maxHeight = Math.max(160, Math.round(vh - r.bottom - 14)) + "px";
    }
    function set(on, focusBack) {
      if (on === open) return;
      open = on; pop.hidden = !on; trigger.setAttribute("aria-expanded", String(on));
      if (on) { pos(); try { pop.focus({ preventScroll: true }); } catch (e) { /* old engines */ } }
      else if (focusBack) { try { trigger.focus({ preventScroll: true }); } catch (e) { /* old engines */ } }
      if (onToggle) onToggle(on);
    }
    function onDown(e) { if (open && !pop.contains(e.target) && !trigger.contains(e.target)) set(false); }
    function onKey(e) { if (open && e.key === "Escape") { e.stopPropagation(); e.preventDefault(); set(false, true); } }
    // touch input does not always produce pointer events (embedded / older WebKit): listen to both
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("touchstart", onDown, { capture: true, passive: true });
    document.addEventListener("keydown", onKey, true);
    window.addEventListener("resize", pos);
    document.addEventListener("scroll", pos, true);
    return {
      toggle: function () { set(!open); }, close: function () { set(false); }, isOpen: function () { return open; }, pos: pos,
      destroy: function () {
        document.removeEventListener("pointerdown", onDown, true); document.removeEventListener("touchstart", onDown, { capture: true });
        document.removeEventListener("keydown", onKey, true);
        window.removeEventListener("resize", pos); document.removeEventListener("scroll", pos, true);
      },
    };
  }
  // Copy on plain-HTTP dashboards over a private network (no secure context, so no navigator.clipboard)
  // and iOS Safari (which drops the user gesture across an await). The text is already in memory; the fallback runs
  // synchronously inside the click. Never a file download — that is the separate, explicit "download" control.
  function copyText(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");  // no on-screen keyboard on iOS
    ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:0;opacity:0;font-size:16px;";
    document.body.appendChild(ta);
    var sel = document.getSelection(), prev = sel && sel.rangeCount ? sel.getRangeAt(0) : null, ok = false;
    try {
      ta.focus({ preventScroll: true });
      ta.select();
      ta.setSelectionRange(0, text.length);  // iOS ignores select() on its own
      ok = document.execCommand("copy");
    } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (prev && sel) { sel.removeAllRanges(); sel.addRange(prev); }
    return ok;
  }
  function copyFeedback(btn, ok) {
    var label = btn.dataset.label || (btn.dataset.label = btn.textContent);
    btn.textContent = ok ? "copied" : "copy failed";
    btn.classList.toggle("mt-bad", !ok);
    clearTimeout(btn._cpT);
    btn._cpT = setTimeout(function () { btn.textContent = label; btn.classList.remove("mt-bad"); }, 1600);
  }
  function copyFrom(btn, text) {
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { copyFeedback(btn, true); },
                                               function () { copyFeedback(btn, copyText(text)); });
      return;
    }
    copyFeedback(btn, copyText(text));  // synchronous: still inside the click gesture
  }
  function download(text) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    a.download = "payload.json";
    a.click();
  }
  // Write markup only when it changed: an identical re-render must not recreate (and repaint) anything.
  function setHTML(el, html) { if (el && el.__html !== html) { el.innerHTML = html; el.__html = html; } }
  // Replace el's children with html, keeping every child whose markup is unchanged (matched by data-key, else data-id):
  // a live update then touches only the rows that are new or changed, never blanks the list, and an open <details>
  // in an untouched card stays open.
  function morph(el, html) {
    var t = document.createElement("template"), old = {};
    t.innerHTML = html;
    Array.prototype.forEach.call(el.children, function (k) { var key = k.dataset.key || k.dataset.id; if (key) old[key] = k; });
    var next = Array.prototype.map.call(t.content.children, function (n) {
      var key = n.dataset.key || n.dataset.id, sig = n.outerHTML, o = key && old[key];
      if (o && o.__sig === sig) { delete old[key]; return o; }
      n.__sig = sig;
      return n;
    });
    next.forEach(function (n, i) { if (el.children[i] !== n) el.insertBefore(n, el.children[i] || null); });
    while (el.children.length > next.length) el.removeChild(el.lastElementChild);
    el.__html = null;
  }
  function mkBtn(label, cls) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "mt-btn" + (cls ? " " + cls : "");
    b.textContent = label;
    return b;
  }

  function scrollTo(el, block) {
    // Scroll within the nearest pane on desktop so the dashboard page itself never jumps; phones scroll natively.
    if (!el) return;
    var c = mm(MOBILE_Q) ? null : el.closest(".mti-pane, .mti-tl, .mti-slist, .mtt-tall");
    if (!c) { el.scrollIntoView({ block: block || "nearest" }); return; }
    var er = el.getBoundingClientRect(), cr = c.getBoundingClientRect();
    if (block === "center") c.scrollTop += er.top - cr.top - (cr.height - er.height) / 2;
    else if (block === "start") c.scrollTop += er.top - cr.top - 8;
    else if (er.top < cr.top) c.scrollTop += er.top - cr.top - 8;
    else if (er.bottom > cr.bottom) c.scrollTop += er.bottom - cr.bottom + 8;
  }

  // ───────────────────────── JSON tree ─────────────────────────
  // Chat-completions arguments, tool outputs and origin blobs arrive as JSON serialized inside a string.
  function parseJSONString(v) {
    if (typeof v !== "string" || v.length < 2) return undefined;
    var t = v.trim(), a = t.charAt(0), z = t.charAt(t.length - 1);
    if (!((a === "{" && z === "}") || (a === "[" && z === "]"))) return undefined;
    try {
      var x = JSON.parse(t);
      return x && typeof x === "object" ? x : undefined;
    } catch (e) { return undefined; }
  }
  function scalarHTML(v, full) {
    if (v === null) return '<span class="mtj-z">null</span>';
    if (typeof v === "boolean") return '<span class="mtj-b">' + v + "</span>";
    if (typeof v === "number") return '<span class="mtj-n">' + v + "</span>";
    var s = String(v), lim = 600;
    if (s.length > lim && !full) {
      return '<span class="mtj-s">"' + esc(s.slice(0, lim)) + '</span><button type="button" class="mtj-more" data-full>… +' + num(s.length - lim) + ' chars</button><span class="mtj-s">"</span>';
    }
    return '<span class="mtj-s">"' + esc(s) + '"</span>';
  }
  // What a collapsed object is, shown in place of its key list: a tool's name, a message's role, a block's type.
  function shapeLabel(v) {
    if (!v || typeof v !== "object" || Array.isArray(v)) return "";
    var fn = v["function"] && typeof v["function"] === "object" ? v["function"] : null;
    var s = typeof v.name === "string" ? v.name : fn && typeof fn.name === "string" ? fn.name
      : typeof v.role === "string" ? v.role : typeof v.type === "string" ? v.type : "";
    return s ? JSON.stringify(s.length > 60 ? s.slice(0, 60) + "…" : s) : "";
  }
  // opts.path ([key, index, …]) opens the nodes leading to one value and marks it .mtj-target (opened opts.targetOpen
  // levels deep); every other node follows the default depth rule. ctx: {on} on that path, {under, until} inside it.
  function jnode(k, v, depth, opts, ctx) {
    var key = k == null ? "" : '<span class="mtj-k">' + esc(typeof k === "number" ? k : JSON.stringify(k)) + "</span>: ";
    var path = opts.path, on = !!(ctx && ctx.on), target = on && path && depth === path.length, under = !!(ctx && ctx.under);
    var parsed = opts.raw ? undefined : parseJSONString(v);
    if (parsed !== undefined) {
      var node = jnode(k, parsed, depth, opts, ctx), sum = node.querySelector("summary");
      if (sum) {
        // a tag that says what this is (passive) plus a labelled action — the tag itself never acts
        var lab = document.createElement("span");
        lab.className = "mt-chip mtj-jstag";
        lab.title = "This value is JSON serialized inside a string; shown parsed";
        lab.textContent = "json in string";
        var tag = document.createElement("button");
        tag.type = "button";
        tag.className = "mt-btn mt-mini mtj-jstr";
        tag.title = "Show the raw string instead of the parsed JSON";
        tag.textContent = "show raw";
        tag.onclick = function (e) {
          e.preventDefault();
          e.stopPropagation();
          node.replaceWith(jnode(k, v, depth, Object.assign({}, opts, { raw: true }), ctx));
        };
        sum.appendChild(lab);
        sum.appendChild(tag);
      }
      return node;
    }
    if (v === null || typeof v !== "object") {
      var d = document.createElement("div");
      d.className = "mtj-row" + (target ? " mtj-target" : "");
      d.innerHTML = key + scalarHTML(v);
      var m = d.querySelector("[data-full]");
      if (m) m.onclick = function () { d.innerHTML = key + scalarHTML(v, true); };
      return d;
    }
    var isA = Array.isArray(v), ks = isA ? v.map(function (_, i) { return i; }) : Object.keys(v);
    var det = document.createElement("details");
    if (target) det.className = "mtj-target";
    var peek = isA ? "" : ks.slice(0, 4).map(esc).join(", ") + (ks.length > 4 ? ", …" : ""), label = shapeLabel(v);
    det.innerHTML = "<summary>" + key + '<span class="mtj-meta">' + (isA ? "[" + ks.length + "]" : "{" + ks.length + "}") +
      (peek ? ' <span class="mtj-peek' + (label ? " has-label" : "") + '">' + peek + "</span>" : "") +
      (label ? ' <span class="mtj-label">' + esc(label) + "</span>" : "") + "</span></summary>";
    var ancestor = on && path && depth < path.length;
    var open = ancestor || target ? true : under ? depth < ctx.until : opts.open != null ? depth < opts.open : depth < 2, built = false;
    function childCtx(ck) {
      if (ancestor && String(ck) === String(path[depth])) return { on: true };
      if (target) return { under: true, until: depth + 1 + (opts.targetOpen || 3) };
      return under ? ctx : null;
    }
    function build() {
      if (built) return;
      built = true;
      var ch = document.createElement("div");
      ch.className = "mtj-ch";
      var CH = 500, shown = 0, at = ancestor ? ks.map(String).indexOf(String(path[depth])) : -1;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "mtj-more";
      function more(n) {
        var end = Math.min(ks.length, shown + Math.max(CH, n || 0));
        for (; shown < end; shown++) ch.insertBefore(jnode(ks[shown], v[ks[shown]], depth + 1, opts, childCtx(ks[shown])), btn);
        if (shown >= ks.length) btn.remove(); else btn.textContent = "show " + Math.min(CH, ks.length - shown) + " more…";
      }
      btn.onclick = function () { more(); };
      ch.appendChild(btn);
      more(at + 1);  // the path's next step is always rendered, however deep in a long list
      det.appendChild(ch);
    }
    det.addEventListener("toggle", function () { if (det.open) build(); });
    if (open && (ks.length < 400 || ancestor || target)) { det.open = true; build(); }
    return det;
  }
  function jsonPanel(title, v, opts) {
    opts = opts || {};
    var wrap = document.createElement("div");
    wrap.className = "mtj-panel" + (opts.quiet ? " mtj-quiet" : "");
    var head = document.createElement("div");
    head.className = "mt-sec";
    head.innerHTML = '<span class="mt-sect">' + esc(title) + "</span>";
    var tools = document.createElement("div");
    tools.className = "mt-tools";
    var bE = mkBtn("expand", "mt-tool"), bC = mkBtn("collapse", "mt-tool"), bCp = mkBtn("copy", "mt-tool");
    var q = document.createElement("input");
    q.type = "search"; q.className = "mt-input mtj-find"; q.placeholder = "find"; q.enterKeyHint = "search";
    q.setAttribute("aria-label", "find in " + title);
    tools.append(bE, bC, bCp, q);
    head.appendChild(tools);
    var body = document.createElement("div");
    body.className = "mtj";
    function render(o) { body.innerHTML = ""; body.appendChild(jnode(null, v, 0, o, o.path ? { on: true } : null)); }
    render(opts);
    bE.onclick = function () { render({ open: 99 }); };
    bC.onclick = function () { render({ open: 1 }); };
    bCp.onclick = function () { copyFrom(bCp, JSON.stringify(v, null, 2)); };
    q.onkeydown = function (e) {
      if (e.key !== "Enter") return;
      var t = q.value.trim();
      if (!t) return render(opts);
      render({ open: 99 });
      var rx = new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), first = null;
      body.querySelectorAll(".mtj-s,.mtj-k,.mtj-n").forEach(function (el) {
        if (el.textContent.toLowerCase().indexOf(t.toLowerCase()) >= 0) {
          el.innerHTML = el.innerHTML.replace(rx, function (m) { return '<mark class="mt-hl">' + m + "</mark>"; });
          first = first || el;
        }
      });
      scrollTo(first, "center");
    };
    wrap.append(head, body);
    return wrap;
  }

  // ───────────────────────── Session & Wire Inspector ─────────────────────────
  var TRIG = { user: 1, subagent: 1, webhook: 1, cron: 1, process: 1, internal: 1, parent: 1, compaction: 1, peer: 1 };
  // Two detail tabs per mode. Transcript = what state.db persisted; Wire = what one captured call actually sent.
  var TTABS = [
    ["readable", "Readable", "What state.db persisted for this row — its text, 💭 thinking, tool calls and results."],
    ["row", "DB Row", "The raw state.db row, every column."]];
  var WTABS = [
    ["readable", "Readable", "The captured request text — state.db content plain; runtime wrappers and injected context highlighted."],
    ["json", "Wire JSON", "The full request envelope as sent, expanded and scrolled to this item."]];
  // tab names from older deep links and saved preferences
  var TAB_ALIAS = { structured: "readable", parsed: "readable", diff: "readable", out: "readable", resp: "readable", req: "json", wire: "json" };
  var WIRE_TABS = /^(diff|req|wire|json|resp|out)$/;  // a deep-linked row with one of these opens on the wire
  function tabName(t) { return TAB_ALIAS[t] || t || "readable"; }
  var LEGEND = [["user", "USER"], ["parent", "PARENT"], ["subagent", "SUBAGENT"], ["webhook", "WEBHOOK"], ["cron", "CRON"], ["process", "PROCESS"],
    ["compaction", "COMPACTION"], ["internal", "INTERNAL"], ["harness", "HARNESS"], ["peer", "PEER"], ["assistant", "ASSISTANT"], ["tool", "TOOL"]];
  // typed provenance columns, in the order the Parsed tab lists them
  var PROV = ["sender_kind", "sender_id", "sent_at", "source_event_id", "intent", "part_kind", "turn_outcome"];
  // "delegate · d2" from a session's lineage summary (typed columns, else parent_session_id)
  function lineageText(lin) {
    if (!lin) return "";
    return (lin.kind || "child") + (lin.depth != null ? " · d" + lin.depth : "");
  }
  // Sessions shown next to a subagent / lineage badge do not repeat it in their name. The prefix comes from Hermes's
  // derived child titles ("Subagent: <assignment>", agent/title_generator.py) and Wiretap's own fallbacks
  // ("Subagent · <id>"); the stored title is untouched and stays available as the tooltip.
  function isChildSession(s) {
    return !!s && (s.source === "subagent" || !!s.parent_session_id || !!(s.lineage && (s.lineage.parent || s.lineage.depth)));
  }
  function bareTitle(t, s) {
    if (!isChildSession(s)) return t;
    return String(t || "").replace(/^\s*Subagent\s*[:·]\s*/i, "").trim() || s.id;
  }
  function lineageChip(lin) {
    if (!lin) return "";
    var t = [lin.typed ? "lineage from typed columns" : "lineage from parent_session_id"];
    if (lin.parent) t.push("parent " + lin.parent);
    if (lin.root) t.push("root " + lin.root);
    return '<span class="mt-chip mt-lin" title="' + esc(t.join(" · ")) + '">' + esc(lineageText(lin)) + "</span>";
  }
  var CALL_RX = /functionCall|tool_use|tool_calls|^function_call$/, RESULT_RX = /functionResponse|tool_result|^function_call_output$/;

  function renderContextGauge(el, m) {
    el.classList.remove("is-stale");
    var shell = { innerHTML: "" };
    gaugeHTML(shell, m);
    setHTML(el, shell.innerHTML);
  }
  function gaugeHTML(el, m) {
    if (!m || !m.id) { el.innerHTML = ""; return; }
    var label = esc(m.title || m.id), identity = '<span><i>session</i> <b title="' + esc(m.id) + '">' + label + '</b></span>';
    if (!m.ctx_window) { el.innerHTML = '<div class="mtt-gk">' + identity + '<span class="mt-dim">context not captured yet</span></div>'; return; }
    var p = m.last_prompt_tokens || 0, W = m.ctx_window, w = function (x) { return (100 * x / W).toFixed(2) + "%"; }, mc = m.message_count || 0;
    var hy = m.hygiene_trigger, co = m.compressor_trigger, lim = m.hygiene_msg_limit;
    el.innerHTML = '<div class="mtt-gk">' + identity + '<span><i>window</i> ' + num(W) +
      '</span><span><i>last prompt</i> <b>' + num(p) + '</b> (' + (100 * p / W).toFixed(1) + '%)</span>' +
      (hy ? '<span style="color:var(--mt-warn)" title="gateway pre-turn hygiene compression">hygiene → ' + num(hy) + '</span>' : '') +
      (co ? '<span style="color:var(--mt-bad)" title="agent context compressor">compressor → ' + num(co) + '</span>' : '<span class="mt-dim">compression off</span>') +
      '<span><i>msgs</i> <b>' + mc + '</b>' + (lim ? '/' + lim : '') + '</span></div>' +
      '<div class="mtt-g"><i style="width:' + w(Math.min(p, W)) + '"></i>' + (hy ? '<u style="left:' + w(hy) + '"></u>' : '') + (co ? '<s style="left:' + w(co) + '"></s>' : '') +
      '<em>' + (100 * p / W).toFixed(1) + '% tokens</em></div>' +
      (lim ? '<div class="mtt-g"><i style="width:' + Math.min(100, 100 * mc / lim) + '%;background:var(--mt-violet)"></i><em>' + mc + '/' + lim + ' msgs</em></div>' : '');
  }

  function mountInspector(root, init) {
    var initMode = init.mode === "transcript" ? "transcript" : init.mode === "wire" || init.mode === "compiled" ? "wire" : null;
    var savedMode = store("mode") === "transcript" ? "transcript" : "wire";
    var S = { sid: null, main: null, rows: [], sel: -1, tabT: tabName(store("dtabT")) === "row" ? "row" : "readable",
      tabW: tabName(store("dtabW")) === "json" ? "json" : "readable", rowCache: {},
      older: null, loading: false, which: "down", tok: 0, firstPaint: null, alive: true, mode: initMode || savedMode,
      comp: null, compLoading: false, csel: null, detail: "row", partCache: {}, wcall: init.call || null, cgen: 0, pendingSel: null };
    if (init.row) S.mode = "transcript";
    if (init.tab) {
      var it0 = tabName(init.tab);
      if (it0 === "row") S.tabT = "row"; else if (it0 === "json") S.tabW = "json";
      if (init.row && WIRE_TABS.test(init.tab)) S.jumpAfter = /^(resp|out)$/.test(init.tab) ? "resp" : "item";
    }
    if (init.call && !init.row) S.mode = "wire";
    root.innerHTML =
      '<div class="mti' + (store("nosb") ? " mti-nosb" : "") + '">' +
      '<div class="mti-top">' +
      '<button type="button" class="mt-btn mti-sbbtn" data-a="sb" title="Sessions (s)"><span aria-hidden="true">☰</span><span class="mti-sid">—</span></button>' +
      '<div class="mt-seg" role="tablist"><button type="button" class="mt-tab" data-mode="wire" title="What the model was actually sent: any captured call\'s system prompt, tools and message window, in wire order (w)">Wire</button>' +
      '<button type="button" class="mt-tab" data-mode="transcript" title="What state.db persisted: every row with its provenance (t)">Transcript</button></div>' +
      '<div class="mti-callnav is-off" role="group" aria-label="Captured call">' +
      '<button type="button" class="mt-btn mt-mini" data-a="cprev" title="Previous call ([)" aria-label="Previous call">‹</button>' +
      '<select class="mt-input mti-callsel" aria-label="Captured call" title="Every captured request of this session — pick one to inspect exactly what it sent"></select>' +
      '<button type="button" class="mt-btn mt-mini" data-a="cnext" title="Next call (])" aria-label="Next call">›</button></div>' +
      '<span class="mti-meta mt-dim"></span>' +
      // Row 2: search, then the filters as labelled groups (a choice for which rows, toggles for what to include), then
      // auto-refresh, which is behaviour, not a filter. Every control is visible at every width: no menu to open.
      '<div class="mti-filters" role="toolbar" aria-label="Message filters">' +
      '<input type="search" class="mt-input mti-q" placeholder="filter messages" aria-label="Filter messages" aria-keyshortcuts="/" title="Filter the list by text (/)">' +
      '<div class="mti-fpanel" role="group" aria-label="Filters">' +
      '<div class="mt-fgroup mti-rowsg" role="radiogroup" aria-label="Rows"><span class="mt-flabel" aria-hidden="true">rows</span>' +
      '<label class="mt-segb" title="Every row"><input type="radio" name="mti-rows" data-rows="all" checked>all</label>' +
      '<label class="mt-segb" title="Only rows with an automatic warning (f)">' +
      '<input type="radio" name="mti-rows" data-f="flag">⚠ flagged</label></div>' +
      '<div class="mt-fgroup" role="group" aria-label="Include"><span class="mt-flabel" aria-hidden="true">include</span>' +
      '<label class="mt-tog" title="Tool results and tool-call-only rows"><input type="checkbox" data-f="tools" checked>tool messages</label>' +
      '<label class="mt-tog" title="Rows that compaction removed (reloads the list)"><input type="checkbox" data-f="inactive">pre-compaction</label>' +
      "</div></div>" +
      helpBtnHTML("mti-fhelp") +
      liveHTML("f", "live", "Refresh about every 8 seconds", "mti-live") +
      "</div></div>" + '<div class="mti-gauge mtt-gauge"></div>' +
      '<div class="mt-pop mti-fhelp" id="mti-fhelp" role="dialog" aria-label="What these controls do" tabindex="-1" hidden><dl>' +
      helpRow("filter messages", "Shows rows containing the text.", "/") +
      helpRow("⚠ flagged", "Rows with an automatic warning, such as a reply describing a tool result that never arrived. A hint, not a confirmed error.", "f") +
      helpRow("tool messages", "Tool results and tool-call-only rows. Hiding them does not change the request.") +
      helpRow("pre-compaction", "Rows that compaction removed. They stay in state.db but are not sent.") +
      helpRow("auto-refresh", "Refreshes about every 8 seconds while you are at the latest item, and shows paused otherwise.", "r") +
      "</dl></div>" +
      '<div class="mti-body">' +
      '<aside class="mti-sb" aria-label="Sessions"><div class="mti-sbhead"><input type="search" class="mt-input mti-sq" placeholder="search sessions" title="All words match across title, ID, model, source, provider, session key and lineage (for example: sol subagent or argon d1)">' +
      '<button type="button" class="mt-btn mti-x" data-a="sbclose" aria-label="Close sessions">✕</button></div><div class="mti-slist"></div></aside>' +
      '<div class="mti-scrim" data-a="scrim"></div>' +
      '<section class="mti-tl"><div class="mt-empty">loading…</div></section>' +
      '<section class="mti-det"><div class="mti-dhead"><button type="button" class="mt-btn mti-back" data-a="back">‹ Back</button>' +
      '<div class="mti-tabs"></div></div><div class="mti-tabhint mt-dim"></div>' +
      '<div class="mti-ref" hidden><span class="mti-refv" title="Exact reference to what is selected — paste it to point at this block"></span>' +
      '<button type="button" class="mt-btn mt-mini" data-a="copyref" title="Copy this reference">copy ref</button></div><div class="mti-pane"><div class="mt-empty">Select a message.</div></div></section>' +
      "</div></div>";
    var $ = function (s) { return root.querySelector(s) || layer.querySelector(s); };
    var $$ = function (s) { return Array.prototype.slice.call(root.querySelectorAll(s)).concat(Array.prototype.slice.call(layer.querySelectorAll(s))); };
    var box = root.querySelector(".mti"), body = root.querySelector(".mti-body"), tl = root.querySelector(".mti-tl"), pane = root.querySelector(".mti-pane");
    var sb = root.querySelector(".mti-sb"), scrim = root.querySelector(".mti-scrim"), det = root.querySelector(".mti-det");
    var f = function (k) { return $('[data-f="' + k + '"]').checked; };
    // Overlays (session drawer, detail sheet) are portalled to <body> when they float: the dashboard's page container is
    // its own stacking context, so a fixed child there would sit under the dashboard header.
    var layer = document.createElement("div");
    layer.className = "mt-root mt-layer";
    document.body.appendChild(layer);
    var fhelp = root.querySelector(".mti-fhelp");
    layer.appendChild(fhelp);
    var hpop = anchoredPop(root.querySelector(".mti-help"), fhelp);
    function place() {
      var drawer = !mm(WIDE_Q), sheet = mm(MOBILE_Q);
      if (drawer) { layer.appendChild(sb); layer.appendChild(scrim); } else { body.insertBefore(scrim, tl); body.insertBefore(sb, scrim); }
      if (sheet) layer.appendChild(det); else body.appendChild(det);
    }
    // the status mirrors the poll's own condition (see the timer below), so it never says "on" while nothing refreshes
    function liveState() {
      if (!f("live")) return "off";
      if (box.classList.contains("mti-det-open")) return "detail";
      if (S.sid && !nearEnd()) return "scrolled";
      return "live";
    }
    var liveRaf = 0;
    function schedLive() { if (!liveRaf) liveRaf = requestAnimationFrame(function () { liveRaf = 0; if (S.alive) setLive(root.querySelector(".mt-live"), liveState()); }); }
    function flag(cls, on) { box.classList.toggle(cls, on); layer.classList.toggle(cls, on); }

    // The panes' height is what is left between their top and the bottom of whatever clips them (the host's
    // overflow-hidden/auto pane, else the viewport), measured — not a guess at the host's chrome. Re-measured whenever
    // something above (host banners, hints, header wrap, gauge) or the viewport changes, so the bottom of every column
    // stays reachable. Header rows keep the tallest height they have shown at this width, so async data and session
    // switches do not collapse and regrow them under the reader.
    var fitRaf = 0, fitWidth = 0, ro = null;
    function clipParent(el) {
      for (var p = el.parentElement; p && p !== document.body && p !== document.documentElement; p = p.parentElement) {
        var oy = getComputedStyle(p).overflowY;
        if (oy !== "visible") return p;
      }
      return null;
    }
    function holdHeight(el) {
      el.style.minHeight = "";
      var h = el.offsetHeight;
      if (h > (+el.dataset.held || 0)) el.dataset.held = h;
      el.style.minHeight = (+el.dataset.held || 0) + "px";
    }
    function fit() {
      fitRaf = 0;
      if (!root.isConnected) return;
      var held = [root.querySelector(".mti-top"), root.querySelector(".mti-gauge")];
      if (window.innerWidth !== fitWidth) {  // wrapping changes with width: forget the held heights
        fitWidth = window.innerWidth;
        held.forEach(function (el) { el.dataset.held = 0; });
      }
      held.forEach(holdHeight);
      if (mm(MOBILE_Q)) { box.style.removeProperty("--mt-body-h"); return; }  // phones: the page scrolls, no fixed panes
      var r = body.getBoundingClientRect(), clip = clipParent(body), gap = 8, avail;
      if (clip) {
        var cr = clip.getBoundingClientRect(), cs = getComputedStyle(clip);
        var top = r.top - cr.top - clip.clientTop + clip.scrollTop;  // in the clip box's content coordinates
        avail = Math.min(clip.clientHeight, window.innerHeight - Math.max(0, cr.top)) - top - (parseFloat(cs.paddingBottom) || 0) - gap;
      } else avail = window.innerHeight - (r.top + (window.scrollY || 0)) - gap;
      var h = Math.max(256, Math.floor(avail)) + "px";
      if (box.style.getPropertyValue("--mt-body-h") !== h) box.style.setProperty("--mt-body-h", h);
    }
    function schedFit() { if (!fitRaf) fitRaf = requestAnimationFrame(fit); }

    function setSheet(open) {
      flag("mti-det-open", !!open);
      schedLive();
      if (typeof schedJump === "function") schedJump();
      document.documentElement.classList.toggle("mt-lock", !!open && mm(MOBILE_Q));
      if (open) pane.scrollTop = 0;
    }
    function setDrawer(open) {
      flag("mti-sb-open", !!open);
      document.documentElement.classList.toggle("mt-lock", !!open && !mm(WIDE_Q) || box.classList.contains("mti-det-open") && mm(MOBILE_Q));
    }

    // sessions
    var sesT = null, sesGen = 0;
    function cleanTitle(s) {
      if (s.display_title) return bareTitle(s.display_title, s);
      var raw = (s.title || "").trim();
      if (/^Subagent:\s*(?:<|\[Parent assignment|[·…#\s]*$)/i.test(raw)) return isChildSession(s) ? s.id : "Subagent · " + s.id;
      var t = bareTitle(raw.replace(/<\/?[a-z_][^>]*(>|$)/gi, "").trim(), s);
      return t === s.id ? t : t.length < 12 ? (t ? t + " (" + s.id + ")" : s.id) : t;
    }
    function loadSessions() {
      var q = $(".mti-sq").value.trim(), g = ++sesGen;
      return api("/inspector/sessions?limit=200&q=" + encodeURIComponent(q)).then(function (d) {
        if (!S.alive || g !== sesGen || q !== $(".mti-sq").value.trim()) return;
        S.main = d.main;
        if (!q) {
          var recent = d.sessions.find(function (s) {
            return !s.parent_session_id && (!s.lineage || !s.lineage.depth) &&
              ["subagent", "cron", "webhook"].indexOf(s.source || "") < 0;
          });
          S.fallback = recent ? recent.id : null;
        }
        $(".mti-slist").innerHTML = d.sessions.map(function (s) {
          return '<button type="button" class="mti-ses' + (s.id === S.sid ? " is-on" : "") + '" data-id="' + esc(s.id) + '">' +
            '<span class="mti-st" title="' + esc(s.title || s.display_title || s.id) + '">' + (s.main ? "★ " : "") + esc(cleanTitle(s)) + "</span>" +
            '<span class="mti-sm"><span class="mt-chip">' + esc(s.source || "?") + "</span><span>" + num(s.message_count) + " msg</span><span>" +
            ago(s.t || s.started_at) + "</span>" + (s.model ? "<span>" + esc(s.model) + "</span>" : "") +
            lineageChip(s.lineage) + "</span></button>";
        }).join("") || '<div class="mt-empty">no sessions</div>';
      }, function (e) {
        if (S.alive && g === sesGen && q === $(".mti-sq").value.trim())
          $(".mti-slist").innerHTML = '<div class="mt-empty mt-bad">' + esc(e.message || e) + "</div>";
      });
    }

    function openSession(id, keepRow) {
      hpop.close();
      S.gen = (S.gen || 0) + 1;  // responses for the previous session are dropped (see loadRows)
      if (S.sid != null && S.sid !== id) { S.wcall = null; S.pendingSel = null; }  // a call id belongs to one session
      S.loading = false; S.compLoading = false; S.total = null; S.srev = null;
      S.sid = id; S.rows = []; S.sel = -1; S.rowCache = {}; S.older = null; S.comp = null; S.csel = null; S.partCache = {};
      // keep the previous session's gauge (dimmed) until this one's arrives: no collapse-and-regrow above the panes
      var gEl = $(".mti-gauge");
      if (id && gEl.firstChild) gEl.classList.add("is-stale"); else renderContextGauge(gEl, id ? { id: id } : null);
      renderCallNav();
      if (id && init.onSessionSelected) init.onSessionSelected(id);
      if (!id) { tl.innerHTML = '<div class="mt-empty">Select a session.</div>'; return Promise.resolve(); }
      if (S.mode === "wire") renderTL(false);
      $$(".mti-ses").forEach(function (e) { e.classList.toggle("is-on", e.dataset.id === id); });
      setDrawer(false);
      setSheet(false);
      return loadRows(false, keepRow).then(function () {
        var tries = 0;
        function hunt() {
          if (!keepRow || !S.older || tries++ > 30 || S.rows.some(function (r) { return String(r.id) === String(keepRow); })) return null;
          return loadRows(true, keepRow).then(hunt);
        }
        return hunt();
      }).then(function () {
        if (!keepRow) return;
        var i = S.rows.findIndex(function (r) { return String(r.id) === String(keepRow); });
        if (i >= 0) { renderTL(false); select(i, true); }
        if (i >= 0 && S.jumpAfter) { var ja = S.jumpAfter; S.jumpAfter = null; rowToWire(S.rows[i], null, ja === "resp"); }
      }).then(function () { if (S.mode === "wire" && !S.comp && !S.compLoading) return loadCompiled(); return null; });
    }

    function loadRows(older, keepRow, poll) {
      if (S.loading) return Promise.resolve();
      S.loading = true;
      var lim = older ? 300 : 250;
      var url = "/inspector/session?id=" + encodeURIComponent(S.sid) + "&limit=" + lim + "&inactive=" + (f("inactive") ? 1 : 0);
      if (older && S.older) url += "&before=" + S.older;
      if (poll && !older && S.srev) url += "&rev=" + encodeURIComponent(S.srev);
      var gen = S.gen;
      return api(url).then(function (d) {
        if (!S.alive || gen !== S.gen) return;  // a session switch happened while this was in flight
        if (d.unchanged) return;  // the server's revision covers every displayed fact (rows, wire mapping, flags)
        if (!older) S.srev = d.rev;
        if (d.context) renderContextGauge($(".mti-gauge"), d.context);
        S.total = d.total;
        var selId = keepRow || (S.rows[S.sel] || {}).id;
        if (older) S.rows = d.rows.concat(S.rows);
        else {
          var firstNew = d.rows.length ? d.rows[0].id : Infinity;
          S.rows = S.rows.filter(function (r) { return r.id < firstNew; }).concat(d.rows);
        }
        if (!older && S.sid !== d.session.id) S.sid = d.session.id;
        S.older = S.rows.length ? S.rows[0].id : null;
        if (d.rows.length < lim && (older || S.rows.length === d.rows.length)) S.older = null;
        S.latestCall = d.latest_call || S.latestCall || null;
        var se = d.session || {};
        $(".mti-sid").textContent = se.title ? cleanTitle(se) : S.sid;
        var metaParts = [se.source, se.model, lineageText(se.lineage), se.lineage && se.lineage.root ? "root " + se.lineage.root : "",
          num(d.total) + " rows", d.matched_calls + " on the wire"].filter(Boolean);
        var metaTxt = metaParts.join(", ");
        // one line, ellipsized (full text on hover): a long model or lineage must not rewrap the header
        // the id is passive text; copying is a labelled action button (a tag shape never acts — it only describes or filters)
        $(".mti-meta").innerHTML = '<span class="mti-sidv" title="Session id">' + esc(se.id || S.sid) + "</span>" +
          '<button type="button" class="mt-btn mt-mini mti-sidcopy" data-a="copysid" title="Copy the session id">copy</button> ' +
          '<span class="mti-metat" title="' + esc(metaTxt) + '">' + metaParts.map(function (x) { return "<span>" + esc(x) + "</span>"; }).join("") + "</span>";
        if (selId) S.sel = S.rows.findIndex(function (r) { return String(r.id) === String(selId); });
        if (S.sel < 0 && S.rows.length && !older && !mm(MOBILE_Q) && S.mode === "transcript") S.sel = S.rows.length - 1;
        if (S.mode === "wire") { if (S.comp) renderTL(false); return; }
        renderTL(!older);
        if (!poll && S.sel >= 0 && (!mm(MOBILE_Q) || box.classList.contains("mti-det-open"))) renderDetail();
      }, function (e) {
        if (gen === S.gen) tl.innerHTML = '<div class="mt-empty mt-bad">' + esc(e.message || e) + "</div>";
      }).then(function () { if (gen === S.gen) S.loading = false; });
    }

    function frChips(r) {
      var fr = r.framing;
      if (!fr) return "";
      var a = fr.first && fr.first.framing, b = fr.latest && fr.latest.framing;
      if (a && b && a !== b) return '<span class="mt-chip mt-flip" title="first ' + a + ", latest replay " + b + '">⚠ ' + a + " → " + b + "</span>";
      var x = a || b;
      return x ? '<span class="mt-chip fr-' + x + '">' + (x === "plain" ? "wire: plain" : "⟨" + x + "⟩") + "</span>" : "";
    }
    function visible(r) {
      if (!f("tools") && r.role === "tool") return false;
      if (f("flag") && !(r.flags && r.flags.length)) return false;
      var q = $(".mti-q").value.trim().toLowerCase();
      if (q && ((r.content || "") + (r.reasoning || "") + (r.tool_names || []).join(" ") + r.label).toLowerCase().indexOf(q) < 0) return false;
      return true;
    }
    function rowHTML(r, i) {
      var chips = [], call = wireFor(r);
      // Navigation is an inline link (underlined text with an arrow), never a tag: tags here are passive metadata.
      // A call or a wire-time addition that can be opened in Wire is a link to that call, on this row's item.
      // The label shortens inside its card (never past its border); the arrow and, for a call, its final id segment stay.
      var go = function (cls, text, title, kind, resp) {
        return '<button type="button" class="mt-link mti-golink ' + cls + '" data-a="towire" data-row="' + r.id + '"' + (kind ? ' data-kind="' + esc(kind) + '"' : "") +
          (resp ? ' data-resp="1"' : "") + ' title="' + esc(title) + '"><span class="mti-golabel">' + text + '</span> <span aria-hidden="true">→</span></button>';
      };
      var wireLabel = function (w) {
        // middle-shortened: "wire h:<session>:<subagent>:" may ellipsize, the call's own segment never does
        var s = String(w), k = s.lastIndexOf(":") + 1;
        if (k <= 0 || s.length - k > 16) k = Math.max(0, s.length - 8);
        return '<span class="mti-gohead">wire ' + esc(s.slice(0, k)) + '</span><span class="mti-gotail">' + esc(s.slice(k)) + "</span>";
      };
      if (r.role === "assistant") chips.push(r.wire ? go("mt-wire", wireLabel(r.wire), "Open the call that produced this reply in Wire\n" + r.wire, null, true) : '<span class="mt-chip mt-dim">no wire</span>');
      if (r.finish_reason) chips.push('<span class="mt-chip">' + esc(r.finish_reason) + "</span>");
      (r.tool_names || []).forEach(function (t) { chips.push('<span class="mt-chip mt-tc">⚙ ' + esc(t) + "</span>"); });
      if (r.tool_call_id) chips.push('<span class="mt-chip mt-dim mti-tcid">' + esc(r.tool_call_id) + "</span>");
      if (r.inject && r.inject.blocks && r.inject.blocks.length) chips.push(call ? go("mt-inj", "+" + r.inject.blocks.map(esc).join(" +"), "Wrapper text added at send time — open this row's item in Wire") : '<span class="mt-chip mt-inj">+' + r.inject.blocks.map(esc).join(" +") + "</span>");
      (r.injections || []).forEach(function (p) {
        var t = "injection part: harness context the wire adds (" + num(p.len) + " chars)";
        chips.push(call ? go("mt-inj", "+" + esc(p.kind || "injection"), t + " — open it in Wire", p.kind || "injection") : '<span class="mt-chip mt-inj" title="' + esc(t) + '">+' + esc(p.kind || "injection") + "</span>");
      });
      var media = (r.parts || []).filter(function (p) { return p.type === "media"; }).length;
      if (media) chips.push('<span class="mt-chip mt-dim">media ×' + media + "</span>");
      if (r.typed && r.kind !== "tool") chips.push('<span class="mt-chip mt-typed" title="classified from typed provenance (sender_kind / parts_json), not from text">typed · ' + esc(r.sender_kind || "?") + "</span>");
      if (r.part_kind && r.kind !== "user") chips.push('<span class="mt-chip mt-dim" title="part_kind">' + esc(r.part_kind) + "</span>");
      if (r.turn_outcome) chips.push('<span class="mt-chip mt-warnc" title="turn_outcome">turn ' + esc(r.turn_outcome) + "</span>");
      if (r.parts_mismatch) chips.push('<span class="mt-chip mt-flip" title="content is not the plain view of parts_json">content ≠ parts</span>');
      chips.push(frChips(r));
      if (r.platform_message_id && r.kind === "user") chips.push('<span class="mt-chip mt-dim">#' + esc(String(r.platform_message_id).slice(-6)) + "</span>");
      else if (r.typed && r.ref && r.kind === "user") chips.push('<span class="mt-chip mt-dim" title="source_event_id">#' + esc(String(r.ref).slice(-6)) + "</span>");
      else if (r.typed && r.ref && r.kind === "subagent") chips.push('<span class="mt-chip mt-dim">' + esc(r.ref) + "</span>");
      if (!r.active) chips.push('<span class="mt-chip">inactive</span>');
      var body = r.content ? '<div class="mti-text">' + esc(r.content) + (r.truncated ? "\n… (" + num(r.content_len) + " chars)" : "") + "</div>"
        : (r.role === "assistant" && !(r.tool_names || []).length ? '<div class="mti-text mt-dim">(empty content)</div>' : "");
      var think = r.reasoning ? '<div class="mti-think">💭 ' + esc(r.reasoning) + "</div>" : "";
      var flags = (r.flags || []).map(function (x) { return '<div class="mt-flag">⚠ ' + esc(x) + "</div>"; }).join("");
      return '<div class="mti-msg k-' + (r.kind || r.role) + (i === S.sel ? " is-sel" : "") + (r.active ? "" : " is-inactive") + '" data-i="' + i + '" tabindex="0">' +
        '<div class="mti-h"><span class="mt-badge">' + esc(r.label) + '</span><span class="mt-chip mt-dim">#' + r.id + "</span>" +
        '<span class="mti-ts">' + shortT(r.timestamp) + "</span></div>" +
        '<div class="mti-chips">' + chips.join("") + "</div>" + flags + think + body + "</div>";
    }
    function pageScroller() {
      // On phones the timeline flows in the dashboard's own scroll container (not necessarily the window).
      for (var p = root.parentElement; p && p !== document.body; p = p.parentElement) {
        var oy = getComputedStyle(p).overflowY;
        if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight + 4) return p;
      }
      return document.scrollingElement || document.documentElement;
    }
    function nearEnd() {
      if (mm(MOBILE_Q)) { var sc = pageScroller(); return sc.scrollTop + sc.clientHeight >= sc.scrollHeight - 160; }
      return tl.scrollTop + tl.clientHeight >= tl.scrollHeight - 60;
    }

    // ↑ Top / ↓ Latest: the views open at the newest item, and on a phone the system prompt, tools and the view
    // switcher are 200+ items up. A floating pair jumps either way in one tap, for whichever container is scrolling:
    // the detail sheet when it is open, else the page (phone) or the timeline pane (desktop).
    var jump = document.createElement("div");
    jump.className = "mti-jump";
    jump.innerHTML = '<button type="button" class="mt-btn" data-j="top" aria-label="Jump to top">↑ Top</button>' +
      '<button type="button" class="mt-btn" data-j="end" aria-label="Jump to latest">↓ Latest</button>' +
      '<button type="button" class="mt-btn mtt-newpill" data-j="new" hidden>↻ New request</button>';
    layer.appendChild(jump);
    function jumpTarget() {
      if (box.classList.contains("mti-det-open") && mm(MOBILE_Q)) return { sc: pane, frame: pane, sheet: true };
      if (mm(MOBILE_Q)) return { sc: pageScroller(), frame: null, sheet: false };
      return { sc: tl, frame: tl, sheet: false };
    }
    var jumpRaf = 0;
    function updJump() {
      jumpRaf = 0;
      if (!root.isConnected) return;
      var t = jumpTarget(), sc = t.sc, top = sc.scrollTop, max = sc.scrollHeight - sc.clientHeight;
      var long = max > 600, up = long && top > 300, down = long && top < max - 300;
      jump.querySelector('[data-j="top"]').hidden = !up;
      var d = jump.querySelector('[data-j="end"]');
      d.hidden = !down;
      d.textContent = t.sheet ? "↓ Bottom" : "↓ Latest";
      var nw = jump.querySelector('[data-j="new"]');
      nw.hidden = !S.compPending;
      jump.classList.toggle("is-on", up || down || !!S.compPending);
      jump.classList.toggle("in-sheet", t.sheet);
      if (t.frame && !mm(MOBILE_Q)) {  // desktop: pin to the timeline pane's bottom-right corner
        var r = t.frame.getBoundingClientRect();
        jump.style.right = Math.max(8, window.innerWidth - r.right + 14) + "px";
        jump.style.bottom = Math.max(8, window.innerHeight - Math.min(r.bottom, window.innerHeight) + 14) + "px";
        jump.style.left = "auto";
      } else { jump.style.right = jump.style.bottom = jump.style.left = ""; }
    }
    function schedJump() { if (!jumpRaf) jumpRaf = requestAnimationFrame(updJump); }
    jump.addEventListener("click", function (e) {
      var b = e.target.closest("[data-j]");
      if (!b) return;
      if (b.dataset.j === "new") {
        var d = S.compPending; S.compPending = null;
        if (d) { var ch = !S.comp || S.comp.call_id !== d.call_id; S.comp = d; if (ch) S.csel = null; renderTL(true); renderDetail(); }
        schedJump();
        return;
      }
      var t = jumpTarget();
      if (b.dataset.j === "top") {
        t.sc.scrollTop = 0;
        if (!t.frame && !t.sheet) window.scrollTo(0, 0);  // the dashboard header lives above the plugin's scroller
      } else if (t.sheet || t.frame) t.sc.scrollTop = t.sc.scrollHeight;
      else { var last = tl.lastElementChild; if (last) last.scrollIntoView({ block: "end" }); else t.sc.scrollTop = t.sc.scrollHeight; }
      schedJump();
    });
    document.addEventListener("scroll", schedJump, true);  // capture: scroll does not bubble from inner containers
    window.addEventListener("resize", schedJump);
    function renderMode() {
      schedJump();
      $$(".mt-seg .mt-tab").forEach(function (b) { b.classList.toggle("is-on", b.dataset.mode === S.mode); });
      box.classList.toggle("mti-wire", S.mode === "wire");
      renderCallNav();
    }
    // The Wire view shows one captured call at a time: S.wcall pins one (null follows the newest).
    function loadCompiled(poll) {
      if ((poll && S.compLoading) || !S.sid) return Promise.resolve();
      S.compLoading = true;
      var cgen = S.gen, lg = ++S.cgen, want = S.wcall;
      var cq = "/inspector/compiled?id=" + encodeURIComponent(S.sid) + (S.clayer === "hermes" ? "&layer=hermes" : "") +
        (want ? "&call=" + encodeURIComponent(want) : "");
      if (poll && S.comp && S.comp.rev) cq += "&rev=" + encodeURIComponent(S.comp.rev);
      return api(cq).then(function (d) {
        if (!S.alive || cgen !== S.gen || lg !== S.cgen) return;  // another session, or a newer load superseded this one
        if (d.unchanged) return;  // nothing displayed changed (server revision over the whole view)
        if (d.context) renderContextGauge($(".mti-gauge"), d.context);
        if (want && d.latest_call === want) S.wcall = null;  // pinned to the newest call: follow new ones
        var changed = !S.comp || S.comp.call_id !== d.call_id || !S.comp.session || S.comp.session.id !== d.session.id;
        if (poll) {
          if (S.csel && changed) { S.compPending = d; schedJump(); return; }  // reading an item of the old request
          S.comp = d;
          renderCallNav();
          if (S.mode === "wire") renderTL(changed);  // timeline only; the open detail stays as it is
          return;
        }
        S.comp = d; S.compPending = null;
        if (S.csel && compiledIds().indexOf(S.csel) < 0 && !itemOf(S.csel)) S.csel = null;
        renderCallNav();
        if (S.mode !== "wire") return;
        renderTL(changed);
        if (!resolvePending() && S.detail === "citem" && S.csel) {
          var el = tl.querySelector('.mti-msg[data-ci="' + S.csel + '"]');
          if (el) { el.classList.add("is-sel"); scrollTo(el, "nearest"); }
          renderDetail();
        }
      }, function (e) {
        if (cgen !== S.gen || lg !== S.cgen) return;
        S.comp = { error: e.message || String(e), session: { id: S.sid } };
        renderCallNav();
        if (S.mode === "wire") renderTL(false);
      }).then(function () { if (cgen === S.gen && lg === S.cgen) S.compLoading = false; });
    }
    function callLabel(x, latest, lane, oneModel) {
      return "Call #" + x.n + " · " + shortT(x.started) + (x.review ? " · [review]" : x.lane && x.lane !== lane ? " · " + x.lane : "") + (x.model && !oneModel ? " · " + x.model : "") +
        (x.status == null ? " · in flight" : x.status !== 200 ? " · HTTP " + x.status : "") + (x.id === latest ? " · latest" : "");
    }
    // An exact, copyable pointer to what is on screen. A wire item's index is its position in that one call's request
    // (it differs between calls), so it is always qualified by the call; a transcript row id is global.
    function currentRef() {
      if (!S.sid) return "";
      var out = ["session=" + S.sid], c = S.comp;
      if (S.mode === "wire") {
        if (c && c.call_id && c.session && c.session.id === S.sid) {
          out.push("call=" + c.call_id);
          var id = S.detail === "citem" ? S.csel : null, it = itemOf(id);
          if (id === "sys") out.push("item=system");
          else if (id === "tools") out.push("item=tools");
          else if (id === "resp") out.push("item=response");
          else if (id && id.indexOf("key:") === 0) out.push("key=" + id.slice(4));
          else if (it) {
            out.push("item=" + ((c.wire && c.wire.list_key) || "items") + "[" + it.i + "]");
            if (it.row_id) out.push("row=" + it.row_id);
          }
        }
      } else if (S.sel >= 0 && S.rows[S.sel]) out.push("row=" + S.rows[S.sel].id);
      return out.join(" ");
    }
    function renderRef() {
      var box2 = $(".mti-ref"), ref = currentRef();
      box2.hidden = !ref;
      $(".mti-refv").textContent = ref;
    }
    function renderCallNav() {
      renderRef();
      var nav = root.querySelector(".mti-callnav"), sel = root.querySelector(".mti-callsel"), c = S.comp;
      var calls = (c && c.calls) || [];
      nav.classList.toggle("is-off", S.mode !== "wire");
      if (S.mode !== "wire") return;
      if (!calls.length) {  // loading, or nothing captured: hold the control's place instead of popping it in later
        sel.innerHTML = '<option disabled selected value="">' + (c && !c.error ? "no captured calls" : c ? "no calls" : "loading calls…") + "</option>";
        nav.querySelector('[data-a="cprev"]').disabled = nav.querySelector('[data-a="cnext"]').disabled = true;
        return;
      }
      var lanes = {};  // the session's usual lane is implied; only an unusual one (e.g. a background fork) is named
      calls.forEach(function (x) { if (!x.review) lanes[x.lane || ""] = (lanes[x.lane || ""] || 0) + 1; });
      var lane = Object.keys(lanes).sort(function (a, b) { return lanes[b] - lanes[a]; })[0];
      var oneModel = calls.every(function (x) { return x.model === calls[0].model; });  // a model shared by every call is noise
      var have = calls.some(function (x) { return x.id === c.call_id; });
      sel.innerHTML = (c.calls_total > calls.length ? '<option disabled value="">' + num(c.calls_total - calls.length) + " older calls not listed</option>" : "") +
        calls.map(function (x) {
          return '<option value="' + esc(x.id) + '"' + (x.id === c.call_id ? " selected" : "") + ">" + esc(callLabel(x, c.latest_call, lane, oneModel)) + "</option>";
        }).join("") + (have || !c.call_id ? "" : '<option selected value="' + esc(c.call_id) + '">' + esc(c.call_id) + "</option>");
      if (!c.call_id) { sel.insertAdjacentHTML("afterbegin", '<option disabled value="">no main call — pick one</option>'); sel.selectedIndex = 0; }
      var i = calls.findIndex(function (x) { return x.id === c.call_id; });
      nav.querySelector('[data-a="cprev"]').disabled = i <= 0;
      nav.querySelector('[data-a="cnext"]').disabled = i < 0 || i >= calls.length - 1;
    }
    function setCall(id) {
      if (!S.comp || !id || id === S.comp.call_id) return;
      S.wcall = id === S.comp.latest_call ? null : id;
      S.compPending = null;
      if (!S.csel) S.detail = "row";
      loadCompiled();
    }
    function stepCall(d) {
      var calls = (S.comp && S.comp.calls) || [], i = calls.findIndex(function (x) { return x.id === S.comp.call_id; });
      if (i >= 0 && calls[i + d]) setCall(calls[i + d].id);
    }
    // Open a transcript row's wire item: the call that first carried it (a reply: the call that produced it).
    function rowToWire(r, kind, resp) {
      if (!r) return;
      var wf = wireFor(r);
      S.pendingSel = resp ? { ci: "resp" } : { row: r.id, kind: kind || null, item: wf && wf.item != null ? wf.item : null };
      S.wcall = wf ? wf.call : null;
      S.mode = "wire"; store("mode", "wire"); S.detail = "citem";
      renderMode();
      if (S.comp && !S.comp.error && S.comp.call_id === S.wcall) {
        if (S.wcall === S.comp.latest_call) S.wcall = null;
        renderTL(true);
        resolvePending();
        return;
      }
      S.comp = null; S.csel = null;
      renderTL(false);
      loadCompiled();
    }
    // after a load: select the item a transcript chip asked for (its injection item, else the row's own item)
    function resolvePending() {
      var p = S.pendingSel, c = S.comp;
      if (!p || !c || !c.wire) return false;
      S.pendingSel = null;
      var id = p.ci || null;
      if (!id) {
        var rid = +p.row, cands = (c.wire.items || []).filter(function (it) {
          return it.row_id === rid || (it.row_ids || []).indexOf(rid) >= 0;
        });
        var hit = (p.kind && cands.filter(function (it) { return it.injection_kind === p.kind; })[0]) ||
          cands.filter(function (it) { return !it.injection_kind; })[0] || cands[0] ||
          (p.item != null ? (c.wire.items || [])[p.item] : null);
        if (hit && hit.folded_into != null) hit = (c.wire.items || [])[hit.folded_into] || hit;
        if (!hit) {
          S.csel = null; S.detail = "row";
          pane.innerHTML = '<div class="mt-empty">Row #' + esc(p.row) + " is not on the wire of call <code>" + esc(c.call_id) + "</code>.</div>";
          return true;
        }
        id = "item:" + hit.i;
      }
      selectC(id, true);
      return true;
    }
    function itemKind(it) {
      if (it.compaction) return "compaction";
      if (it.item_kind) return it.item_kind;
      if (it.row_kind) return it.row_kind;
      var r = it.role || "";
      if (CALL_RX.test(r) || r === "model" || r === "assistant") return "assistant";
      if (RESULT_RX.test(r) || r === "tool") return "tool";
      if (r === "system" || r === "developer") return "system";
      return it.framing === "SYSTEM_MESSAGE" ? "internal" : "user";
    }
    function itemLabel(it) {
      if (it.compaction) return "COMPACTION SUMMARY";
      if (it.item_label) return it.item_label;
      if (it.row_label) return it.row_label;
      var r = it.role || "?";
      if (CALL_RX.test(r)) return "ASSISTANT · tool call";
      if (RESULT_RX.test(r)) return "TOOL RESULT";
      return r.toUpperCase();
    }
    function compiledIds() {
      var c = S.comp, w = c && c.wire, ids = [];
      if (!w || w.error) return ids;
      ids.push("sys");
      if (c.tool_names) ids.push("tools");
      (w.items || []).forEach(function (it) { if (itemVisible(it)) ids.push("item:" + it.i); });
      ids.push("resp");
      return ids;
    }
    function itemOf(id) { var w = S.comp && S.comp.wire; return w && id && id.indexOf("item:") === 0 ? (w.items || [])[+id.slice(5)] : null; }
    function itemVisible(it) {
      if (it.folded_into != null) return false;  // shown inside the assistant turn it belongs to
      var k = itemKind(it);
      if (!f("tools") && k === "tool") return false;
      if (!f("tools") && CALL_RX.test(it.role || "") && !it.head) return false;
      if (f("flag") && !(it.row_flags && it.row_flags.length)) return false;
      var q = $(".mti-q").value.trim().toLowerCase();
      if (q && ((it.head || "") + itemLabel(it)).toLowerCase().indexOf(q) < 0) return false;
      return true;
    }
    function renderCompiled(scrollEnd) {
      var c = S.comp, atEnd = nearEnd();
      if (!c) { tl.innerHTML = '<div class="mt-empty">' + (S.wcall ? "loading call " + esc(S.wcall) + "…" : "compiling…") + "</div>"; return; }
      if (c.error && !c.wire) {
        tl.innerHTML = '<div class="mt-empty">' + esc(c.error) + ((c.calls || []).length ? '<div class="mt-hint">Use the call picker above.</div>'
          : '<div class="mt-hint">The plugin captures every model call Hermes makes once it is enabled (<code>hermes plugins enable wiretap</code>) and the gateway or CLI has restarted.</div>') +
          '<br><button type="button" class="mt-btn" data-mode="transcript">open the transcript instead</button></div>';
        return;
      }
      var w = c.wire, m = w.meta || {}, call = w.call || {}, sy = c.system || {};
      var keyNames = (w.keys || []).filter(function (k) { return !k.list && k.key !== sy.key && k.key !== "tools"; });
      var lay = w.layer === "wire" ? '<span class="mt-chip mt-wire" title="The exact body sent over HTTP, after the provider adapter rewrote Hermes\'s messages">wire · post-adapter</span>'
        : w.layer === "hermes" && w.which === "hermes" ? '<span class="mt-chip mt-inj" title="Hermes\'s own messages, before the provider adapter rewrote them">Hermes · pre-adapter</span>'
        : '<span class="mt-chip mt-inj" title="Captured from Hermes\'s request hook: what Hermes handed its provider client. The provider SDK or an adapter may still change it before it is sent">Hermes request · adapter input</span>';
      var layBtn = w.has_hermes && w.layer !== "hermes" || w.which === "hermes"
        ? '<button type="button" class="mt-btn mt-mini" data-a="clayer">' + (w.which === "hermes" ? "show wire (post-adapter)" : "show Hermes pre-adapter") + "</button>" : "";
      var calls = c.calls || [], me = calls.filter(function (x) { return x.id === c.call_id; })[0], newer = 0;
      calls.forEach(function (x) { if (me && x.n > me.n) newer++; });
      var html = '<div class="mt-card mti-csum"><div class="mti-csumh"><b>Compiled request</b>' + (me ? '<span class="mt-chip">call #' + me.n + "</span>" : "") + lay +
        '<span class="mt-chip mt-dim">' + esc(c.call_id) + "</span>" + layBtn + '<span class="mti-ts">' + shortT(m.started) + "</span></div>" +
        '<div class="mtt-cm"><span><i>items</i> ' + num((w.items || []).length) + "</span><span><i>prompt</i> " + num(call.prompt_tokens) + "</span><span><i>cached</i> " +
        (call.hit_pct == null ? "—" : call.hit_pct + "%") + "</span><span><i>model</i> " + esc(m.model || "") + "</span><span><i>bytes</i> " + num(m.req_bytes) + "</span></div>" +
        '<div class="mti-chips">' +
        (me && me.review ? '<span class="mt-chip mt-inj" title="A background memory/skill review: a fork that reuses this session\'s id and cached prefix; it is not the conversation\'s own request">background review</span>' : "") +
        (c.historic && c.latest_call ? (me && me.review ? "" : '<span class="mt-chip mt-warnc" title="Not the session\'s newest conversational call">' + newer + " newer call" + (newer === 1 ? "" : "s") + "</span>") +
          '<button type="button" class="mt-link mti-golink mt-warnc" data-a="clatest" title="Open the session\'s newest conversational call">' +
          (me && me.review ? "back to the latest main call" : "open the latest") + ' <span aria-hidden="true">→</span></button>' : "") +
        (c.call_missing ? '<span class="mt-chip mt-flip" title="that call is not captured (retention, or another session) — showing the newest">call ' + esc(c.call_missing) + " not found</span>" : "") +
        (c.call_id !== c.correlated_call && !c.historic ? '<span class="mt-chip" title="newest captured request that extends the last correlated call">newest extension of ' + esc(c.correlated_call) + "</span>" : "") +
        (m.status == null ? '<span class="mt-chip mt-warnc" title="request sent, response not received yet">in flight</span>' : "") +
        (m.exact !== 0 ? "" : m.tools_exact === 1
          ? '<span class="mt-chip mt-warnc" title="Messages, system prompt and tools are complete. The other request parameters come from Hermes\'s size-capped hook copy and may be cut or absent">parameters from hook copy</span>'
          : '<span class="mt-chip mt-warnc" title="Messages and system prompt are complete. Tools and parameters come from Hermes\'s size-capped hook copy: long or deeply nested values may be cut, and they are absent when the request exceeded the cap">envelope from hook copy</span>') +
        (w.has_upstream ? '<span class="mt-chip mt-wire" title="a proxy log for this call was merged">+ proxy upstream</span>' : "") +
        ((c.rows_after || []).length ? '<span class="mt-chip mt-warnc" title="transcript rows written after this request was sent">' + c.rows_after.length + " newer rows not yet on the wire</span>" +
          '<button type="button" class="mt-link mti-golink mt-warnc" data-a="after" title="Scroll to the rows written after this request">jump to them <span aria-hidden="true">↓</span></button>' : "") +
        (c.archived_count ? '<span class="mt-chip">' + num(c.archived_count) + " archived rows not sent</span>" : "") +
        (c.rows_unmapped ? '<span class="mt-chip" title="active transcript rows that did not align to a wire item">' + c.rows_unmapped + " active rows unaligned</span>" : "") + "</div></div>";
      var sel = function (id) { return S.detail === "citem" && S.csel === id ? " is-sel" : ""; };
      html += '<div class="mti-msg k-system' + sel("sys") + '" data-ci="sys" tabindex="0"><div class="mti-h"><span class="mt-badge">SYSTEM PROMPT</span><span class="mt-chip mt-dim">' +
        esc(sy.key || (sy.item != null ? (w.list_key || "messages") + "[" + sy.item + "]" : "none")) + '</span><span class="mti-ts">' + num(sy.wire_len) + " chars</span></div>" +
        '<div class="mti-chips">' + sysChip(sy) + "</div></div>";
      if (c.tool_names) {
        html += '<div class="mti-msg k-tool' + sel("tools") + '" data-ci="tools" tabindex="0"><div class="mti-h"><span class="mt-badge">TOOLS</span><span class="mt-chip mt-dim">' + c.tool_names.length +
          ' declarations</span></div><div class="mti-chips">' + c.tool_names.slice(0, 14).map(function (n) { return '<span class="mt-chip mt-tc">' + esc(n) + "</span>"; }).join("") +
          (c.tool_names.length > 14 ? '<span class="mt-chip">+' + (c.tool_names.length - 14) + "</span>" : "") + "</div></div>";
      }
      if (keyNames.length) html += '<div class="mti-envelope mt-dim">envelope: ' + keyNames.map(function (k) { return '<button type="button" class="mt-link" data-ci="key:' + esc(k.key) + '">' + esc(k.key) + "</button>"; }).join(" · ") + "</div>";
      if (f("inactive")) {
        var arch = [];
        S.rows.forEach(function (r, i) { if (!r.active && visible(r)) arch.push(rowHTML(r, i)); });
        html += '<details class="mti-archived"><summary>pre-compaction history · ' + num(c.archived_count) + " rows in state.db · not part of this request" +
          (arch.length < (c.archived_count || 0) ? " (latest " + arch.length + ' loaded)' : "") + "</summary>" +
          (S.older ? '<div class="mti-turn"><button type="button" class="mt-btn" data-a="older">load older</button></div>' : "") + arch.join("") + "</details>";
      }
      html += '<div class="mti-turn"><span>message window · wire order</span></div>';
      var rowById = {};
      S.rows.forEach(function (r) { rowById[r.id] = r; });
      (w.items || []).forEach(function (it) {
        if (!itemVisible(it)) return;
        var id = "item:" + it.i, k = itemKind(it);
        var chips = ['<span class="mt-chip mt-dim">' + esc(it.role) + "</span>"];
        if (it.framing && it.framing !== "plain") chips.push('<span class="mt-chip fr-' + it.framing + '">⟨' + it.framing + "⟩</span>");
        chips.push('<span class="mt-chip mt-dim">' + num(it.len) + " ch</span>");
        if (it.reasoning && it.reasoning.length) {
          var rc = it.reasoning.reduce(function (a, x) { return a + (x.summary ? x.summary.length : 0); }, 0);
          chips.push('<span class="mt-chip mt-think" title="reasoning item' + (it.reasoning.length > 1 ? "s" : "") + " #" + it.reasoning.map(function (x) { return x.i; }).join(", #") +
            ' folded into this turn">💭 reasoning' + (rc ? " · " + num(rc) + " ch summary" : " · encrypted") + "</span>");
        }
        var rr = it.row_id ? rowById[it.row_id] : null;
        if (rr && rr.tool_names) rr.tool_names.forEach(function (t) { chips.push('<span class="mt-chip mt-tc">⚙ ' + esc(t) + "</span>"); });
        if (it.row_id) chips.push('<span class="mt-chip">row #' + it.row_id + ((it.row_ids || []).length > 1 ? " +" + (it.row_ids.length - 1) : "") + "</span>");
        else chips.push('<span class="mt-chip mt-dim" title="no transcript row aligned to this item">no row</span>');
        html += '<div class="mti-msg k-' + k + sel(id) + '" data-ci="' + id + '" tabindex="0"><div class="mti-h"><span class="mt-badge">' + esc(itemLabel(it)) +
          '</span><span class="mt-chip mt-dim">#' + it.i + '</span></div><div class="mti-chips">' + chips.join("") + "</div>" +
          (it.row_flags || []).map(function (x) { return '<div class="mt-flag">⚠ ' + esc(x) + "</div>"; }).join("") +
          (it.head ? '<div class="mti-text">' + esc(it.head) + (it.len > 220 ? " …" : "") + "</div>" : "") + "</div>";
      });
      // what this call got back: the turn the request above produced
      var p = w.response || {}, ptc = p.tool_calls || [];
      html += '<div class="mti-turn"><span>model output · this call\'s response</span></div>' +
        '<div class="mti-msg k-assistant' + sel("resp") + '" data-ci="resp" tabindex="0"><div class="mti-h"><span class="mt-badge">MODEL OUTPUT</span>' +
        '<span class="mt-chip mt-dim">' + esc(c.call_id) + '</span><span class="mti-ts">' + shortT(m.ended) + "</span></div>" +
        '<div class="mti-chips">' + (m.status == null ? '<span class="mt-chip mt-warnc">awaiting response</span>' : m.status !== 200 ? '<span class="mt-chip mt-flip">HTTP ' + esc(m.status) + "</span>" : "") +
        (p.finish ? '<span class="mt-chip">' + esc(p.finish) + "</span>" : "") +
        (call.output_tokens != null ? '<span class="mt-chip mt-dim">' + num(call.output_tokens) + " out</span>" : "") +
        (p.thinking ? '<span class="mt-chip mt-think">💭 ' + num(p.thinking.length) + " ch</span>" : "") +
        ptc.map(function (t) { return '<span class="mt-chip mt-tc">⚙ ' + esc(t.name || "?") + "</span>"; }).join("") + "</div>" +
        (p.text ? '<div class="mti-text">' + esc(p.text.slice(0, 220)) + (p.text.length > 220 ? " …" : "") + "</div>" : "") + "</div>";
      if ((c.rows_after || []).length) {
        html += '<div class="mti-turn mti-after"><span>written after this request · next turn</span></div>' + c.rows_after.map(function (r) {
          var i = S.rows.findIndex(function (x) { return x.id === r.id; });
          return '<div class="mti-msg k-' + r.kind + ' is-pending"' + (i >= 0 ? ' data-i="' + i + '"' : "") + '><div class="mti-h"><span class="mt-badge">' + esc(r.label) +
            '</span><span class="mt-chip mt-dim">#' + r.id + '</span><span class="mt-chip mt-warnc">not yet on the wire</span></div></div>';
        }).join("");
      }
      tl.innerHTML = html;
      var fp = "c:" + S.sid + ":" + c.call_id;
      if (scrollEnd && (atEnd || S.firstPaint !== fp) && !(S.detail === "citem" && S.csel)) {
        if (mm(MOBILE_Q)) { if (S.firstPaint !== fp) { var last = tl.lastElementChild; if (last) last.scrollIntoView({ block: "end" }); } }
        else tl.scrollTop = tl.scrollHeight;
      }
      S.firstPaint = fp;
    }
    function sysChip(sy) {
      if (!sy.stored_len) return '<span class="mt-chip mt-dim">no stored copy</span>';
      if (sy.matches_stored) return '<span class="mt-chip mt-wire" title="the wire system prompt is exactly the prompt state.db stored for this session">matches state.db</span>';
      return '<span class="mt-chip mt-inj" title="Hermes stored one prompt for the session; plugins may add sections at send time">state.db stored ' + num(sy.stored_len) + " chars (" +
        (sy.wire_len - sy.stored_len >= 0 ? "+" : "") + num(sy.wire_len - sy.stored_len) + " on wire)</span>";
    }
    function selectC(id, scroll, noSheet) {
      S.csel = id;
      S.detail = "citem";
      $$(".mti-msg.is-sel").forEach(function (e) { e.classList.remove("is-sel"); });
      var el = tl.querySelector('.mti-msg[data-ci="' + id + '"]');
      if (el) { el.classList.add("is-sel"); if (scroll) scrollTo(el, "center"); }
      if (mm(MOBILE_Q) && !noSheet) setSheet(true);
      renderDetail();
    }
    function stepC(d) {
      var ids = compiledIds(), i = ids.indexOf(S.csel) + d;
      if (S.csel == null) i = d > 0 ? 0 : ids.length - 1;
      if (i >= 0 && i < ids.length) selectC(ids[i], true, true);
    }
    function part(q, which, route) {
      var wh = which || (S.comp.wire && S.comp.wire.which === "hermes" ? "hermes" : "down");
      var rev = S.comp.rev, key = (route || "part") + "|" + partKey(S.comp.call_id, wh, q, rev);
      if (S.partCache[key]) return Promise.resolve(S.partCache[key]);
      return api("/inspector/wire/" + (route || "part") + "?" + partQuery(S.comp.call_id, wh, q)).then(function (v) {
        if (S.comp && S.comp.rev === rev) S.partCache[key] = v;  // a late answer for an older view is not cached
        return v;
      });
    }
    function readable(q) { return part(q, null, "readable"); }
    function textOf(v) {
      var out = [];
      (function walk(x, k) {
        if (typeof x === "string") { if (k === "text" || k === "content" || k === "output" || k === "arguments" || k === "thinking" || k == null) out.push(x); }
        else if (Array.isArray(x)) x.forEach(function (y) { walk(y, k); });
        else if (x && typeof x === "object") Object.keys(x).forEach(function (kk) {
          if (kk !== "thoughtSignature" && kk !== "signature" && kk !== "data" && kk !== "inlineData") walk(x[kk], kk);
        });
      })(v, null);
      return out.join("\n\n");
    }
    // Tool calls/results are structured on the wire in every provider format; normalize for display.
    function structuredOf(v) {
      var out = { thinking: [], text: [], calls: [], results: [] };
      function result(name, id, val) { out.results.push({ name: name, id: id, output: val }); }
      function block(b) {
        if (!b || typeof b !== "object") return;
        if (b.functionCall) out.calls.push({ name: b.functionCall.name, id: b.functionCall.id, args: b.functionCall.args });
        else if (b.functionResponse) result(b.functionResponse.name, b.functionResponse.id, b.functionResponse.response);
        else if (b.type === "tool_use") out.calls.push({ name: b.name, id: b.id, args: b.input });
        else if (b.type === "tool_result") result(null, b.tool_use_id, b.content);
        else if (b.type === "function_call") out.calls.push({ name: b.name, id: b.call_id || b.id, args: b.arguments });
        else if (b.type === "function_call_output") result(null, b.call_id, b.output);
        else if (b.type === "thinking" || b.type === "reasoning" || b.thought === true) {
          var th = b.thinking || b.text || (Array.isArray(b.summary) ? b.summary.map(function (x) { return x && x.text; }).filter(Boolean).join("\n") : "");
          if (th) out.thinking.push(th);
        } else if (typeof b.text === "string" && b.text) out.text.push(b.text);
      }
      var list = Array.isArray(v.parts) ? v.parts : Array.isArray(v.content) ? v.content : null;
      if (list) list.forEach(block); else block(v);
      if (Array.isArray(v.tool_calls)) v.tool_calls.forEach(function (t) {
        var fn = t["function"] || {};
        out.calls.push({ name: fn.name || t.name, id: t.id, args: fn.arguments != null ? fn.arguments : t.arguments });
      });
      if (v.role === "tool") result(v.name, v.tool_call_id, v.content);
      else if (typeof v.content === "string" && v.content && !list) out.text.push(v.content);
      var rc = v.reasoning_content || v.reasoning;
      if (typeof rc === "string" && rc) out.thinking.push(rc);
      return out;
    }
    function valuePanel(title, val, quiet) {
      // A parsed object/array gets the tree (JSON-in-string included); plain text keeps its line breaks.
      var obj = val && typeof val === "object" ? val : parseJSONString(val);
      if (obj !== undefined) return jsonPanel(title, obj, { open: 3, quiet: quiet });
      var d = document.createElement("div");
      d.className = "mtj-panel" + (quiet ? " mtj-quiet" : "");
      var text = val == null ? "(empty)" : String(val);
      d.innerHTML = '<div class="mt-sec"><span class="mt-sect">' + esc(title) + '</span><span class="mt-tools"></span></div><pre class="mt-pre">' + esc(text) + "</pre>";
      var b = mkBtn("copy", "mt-tool");
      b.onclick = function () { copyFrom(b, text); };
      d.querySelector(".mt-tools").appendChild(b);
      return d;
    }
    function shortId(id) { id = String(id); return id.length > 20 ? id.slice(0, 9) + "…" + id.slice(-6) : id; }
    function toolCard(kind, name, n, total, id, panel) {
      // The tool's name is the card's title; ordinal and call id are quiet metadata; the body sits inside the card.
      var card = document.createElement("div");
      card.className = "mt-card mti-tcard mti-tcard-" + kind;
      card.innerHTML = '<div class="mti-tch"><span class="mti-tname">' + esc(name || (kind === "call" ? "?" : "result")) + "</span>" +
        '<span class="mti-tmeta">' + (kind === "call" ? "tool call" : "tool result") + (total > 1 ? " " + (n + 1) : "") +
        (id ? ' · <code class="mti-tid" title="' + esc(id) + '">' + esc(shortId(id)) + "</code>" : "") + "</span></div>";
      card.appendChild(panel);
      return card;
    }
    function renderStructured(st, resultName) {
      var frag = document.createDocumentFragment();
      function sec(html) { var d = document.createElement("div"); d.innerHTML = html; frag.appendChild(d); }
      st.thinking.forEach(function (t) { sec('<div class="mt-sec"><span class="mt-sect">thinking</span></div><pre class="mt-pre mt-thinkpre">' + esc(t) + "</pre>"); });
      st.text.forEach(function (t) { sec('<div class="mt-sec"><span class="mt-sect">text</span></div><pre class="mt-pre">' + esc(t) + "</pre>"); });
      var callName = {};
      st.calls.forEach(function (c) { if (c.id) callName[c.id] = c.name; });
      st.calls.forEach(function (c, n) {
        frag.appendChild(toolCard("call", c.name, n, st.calls.length, c.id, valuePanel("arguments", c.args, true)));
      });
      st.results.forEach(function (r, n) {
        var o = r.output;
        // Gemini wraps text results as {output: "..."}; show the inner value directly.
        if (o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === 1 && (o.output != null || o.result != null)) o = o.output != null ? o.output : o.result;
        if (Array.isArray(o) && o.every(function (x) { return x && x.type === "text"; })) o = o.map(function (x) { return x.text; }).join("\n");
        frag.appendChild(toolCard("result", r.name || callName[r.id] || (st.results.length === 1 ? resultName : ""), n, st.results.length,
                                  r.id, valuePanel("output", o, true)));
      });
      return frag;
    }
    function itemRow(it) {
      // the aligned transcript row (loaded page first, else enough to render it; DB Row fetches the full row)
      if (!it || !it.row_id) return null;
      var r = S.rows.filter(function (x) { return x.id === it.row_id; })[0];
      return r || { id: it.row_id, kind: it.row_kind, label: it.row_label, flags: it.row_flags, role: it.row_kind === "assistant" ? "assistant" : "" };
    }
    function secH(t, cls) { return '<div class="mt-sec"><span class="mt-sect' + (cls ? " " + cls : "") + '">' + esc(t) + "</span></div>"; }
    // One wire string as it went out: state.db's own content in plain text; wrappers and injected context the runtime
    // built around it highlighted inline, each run titled with what it is.
    function runsHTML(rd) {
      var segs = (rd && rd.segments) || [];
      if (!segs.length) return "";
      var kinds = {}, how = {}, unal = false;
      var body = segs.map(function (s) {
        (s.matched || []).forEach(function (m) { how[m.how] = 1; });
        var html = s.runs.map(function (r) {
          if (r.k === "raw") { kinds.raw = 1; return '<span class="mtw-raw" title="' + esc(r.label || "state.db") + '">' + esc(r.t) + "</span>"; }
          if (r.k === "unaligned") { unal = true; return esc(r.t); }
          var inj = r.k === "injection", lab = r.label || "runtime";
          kinds[(inj ? "i:" : "w:") + lab] = r.persisted;
          var tip = (inj ? "injected · " : "wrapper · ") + lab + (r.persisted === true ? " · also stored in api_content" : r.persisted === false ? " · wire only" : "");
          return '<span class="' + (inj ? "mtw-inj" : "mtw-wrap") + '" title="' + esc(tip) + '">' + esc(r.t) + "</span>";
        }).join("");
        return (segs.length > 1 ? '<div class="mtw-path">' + esc(s.path) + " · " + num(s.len) + " ch</div>" : "") +
          '<pre class="mt-pre mtw">' + html + "</pre>" + (s.too_large ? '<div class="mt-hint mt-dim">too large to separate — shown verbatim</div>' : "");
      }).join("");
      var legend = (kinds.raw ? '<span class="mtw-key mtw-raw">state.db content</span>' : "") + Object.keys(kinds).filter(function (k) { return k !== "raw"; }).map(function (k) {
        var inj = k.charAt(0) === "i";
        return '<span class="mtw-key ' + (inj ? "mtw-inj" : "mtw-wrap") + '">' + (inj ? "+" : "") + esc(k.slice(2)) + "</span>";
      }).join("");
      var note = unal ? "no transcript row aligned to this item — only its tags are highlighted"
        : (rd.source || []).indexOf("parts") >= 0 ? "raw = typed authored parts (parts_json); + = typed injection parts"
        : (rd.source || []).indexOf("prompt") >= 0 ? "raw = the system prompt state.db stored for the session" : "raw = the row's state.db content";
      if (how.lines) note += " · matched line by line (whitespace differs)";
      return '<div class="mtw-legend">' + legend + '<span class="mt-dim mtw-note">' + esc(note) + "</span></div>" + body;
    }
    function toolList(v) {
      var out = [];
      (Array.isArray(v) ? v : []).forEach(function (t) {
        if (!t || typeof t !== "object") return;
        (t.functionDeclarations || []).forEach(function (fd) { out.push(fd); });
        if (t["function"] && typeof t["function"] === "object") out.push(t["function"]);
        else if (t.name) out.push(t);
      });
      return out;
    }
    function itemHead(it) {
      return '<div class="mti-msg k-' + itemKind(it) + ' is-static"><div class="mti-h"><span class="mt-badge">' + esc(itemLabel(it)) + '</span><span class="mt-chip mt-dim">#' + it.i +
        '</span><span class="mti-ts">' + num(it.len) + " ch</span></div>" + (it.row_flags || []).map(function (x) { return '<div class="mt-flag">⚠ ' + esc(x) + "</div>"; }).join("") + "</div>";
    }
    function renderCompiledDetail(tok) {
      var c = S.comp, id = S.csel, w = c && c.wire;
      renderTabs(WTABS, S.tabW);
      if (!w) { pane.innerHTML = '<div class="mt-empty">no compiled request</div>'; return null; }
      var it = itemOf(id), sy = c.system || {}, list = w.list_key || "messages";
      if (id.indexOf("item:") === 0 && !it) { pane.innerHTML = '<div class="mt-empty">This call has no item ' + esc(id.slice(5)) + ".</div>"; return null; }
      var path = id === "sys" ? (sy.key ? [sy.key] : sy.item != null ? [list, sy.item] : null) : id === "tools" ? ["tools"]
        : id.indexOf("key:") === 0 ? [id.slice(4)] : it ? [list, it.i] : null;
      if (S.tabW === "json") return wireJSON(path, id === "resp", tok, it);
      if (id === "resp") return respReadable(tok);
      if (id === "sys") {
        var sysLabel = sy.key || (sy.item != null ? list + "[" + sy.item + "]" : "system");
        if (!sy.key && sy.item == null) { pane.innerHTML = '<div class="mt-empty">This request carries no system prompt.</div>'; return null; }
        return readable("part=sys&session=" + encodeURIComponent(S.sid)).then(function (rd) {
          if (S.tok !== tok) return;
          pane.innerHTML = '<div class="mti-msg k-system is-static"><div class="mti-h"><span class="mt-badge">SYSTEM PROMPT</span><span class="mt-chip mt-dim">' + esc(sysLabel) +
            '</span><span class="mti-ts">' + num(sy.wire_len) + ' chars</span></div><div class="mti-chips">' + sysChip(sy) + "</div></div>" + (runsHTML(rd) || '<div class="mt-empty">no text</div>');
        });
      }
      if (id === "tools" || id.indexOf("key:") === 0) {
        var key = id === "tools" ? "tools" : id.slice(4);
        return part("part=key&key=" + encodeURIComponent(key)).then(function (v) {
          if (S.tok !== tok) return;
          var tl2 = key === "tools" ? toolList(v) : [];
          pane.innerHTML = '<div class="mti-msg k-tool is-static"><div class="mti-h"><span class="mt-badge">' + esc(key === "tools" ? "TOOLS" : key) + "</span>" +
            (key === "tools" ? '<span class="mti-ts">' + tl2.length + " declarations</span>" : "") + "</div></div>";
          if (key !== "tools") { pane.appendChild(valuePanel(key, v)); return; }
          pane.insertAdjacentHTML("beforeend", '<div class="mti-tools">' + tl2.map(function (t) {
            var d = String(t.description || "").replace(/\s+/g, " ").trim();
            return '<div class="mti-tool"><span class="mt-chip mt-tc">' + esc(t.name || "?") + '</span><span class="mt-dim">' + esc(d.slice(0, 220)) + (d.length > 220 ? " …" : "") + "</span></div>";
          }).join("") + "</div>");
        });
      }
      var r = itemRow(it), rs = it.reasoning || [];
      var rows = it.row_id ? (it.row_ids && it.row_ids.length > 1 ? it.row_ids : [it.row_id]) : [];
      var assistant = itemKind(it) === "assistant" || CALL_RX.test(it.role || "") || it.role === "model";
      return Promise.all([part("part=item&i=" + it.i), assistant ? null : readable("part=item&i=" + it.i + "&rows=" + rows.join(","))]).then(function (got) {
        if (S.tok !== tok) return;
        var v = got[0], rd = got[1];
        var html = itemHead(it) + kv([["position", "item " + it.i + " of " + (w.items || []).length + " · " + esc(list)], ["wire role", esc(it.role)],
          ["transcript row" + (rows.length > 1 ? "s" : ""), rows.length ? rows.map(function (x) {
            return '<button type="button" class="mt-link" data-a="torow" data-row="' + x + '">#' + x + " →</button>";
          }).join(" ") + " " + esc(it.row_label) + (it.align ? ' <span class="mt-dim">(by ' + esc(it.align) + ")</span>" : "") : "not aligned to a transcript row"]]);
        html += rs.map(function (x) {
          return secH("💭 reasoning · item #" + x.i, "mt-thinkh") + (x.summary ? '<pre class="mt-pre mt-thinkpre">' + esc(x.summary) + "</pre>"
            : '<div class="mt-dim mt-hint">encrypted reasoning (' + num(x.encrypted_chars) + " chars) — the provider returns it opaque; only it can read it back</div>");
        }).join("");
        var st = structuredOf(v || {}), segs = rd && rd.segments && rd.segments.length;
        // structured content (tool calls/results; an assistant turn's text and thinking) renders once, as cards —
        // never also as the flattened text dump, which would print an assistant reply twice
        var cards = st.calls.length || st.results.length || (assistant && (st.text.length || st.thinking.length));
        if (segs) html += runsHTML(rd);
        else if (!cards) { var tx = textOf(v); if (tx) html += '<pre class="mt-pre">' + esc(tx) + "</pre>"; }
        pane.innerHTML = html;
        if (cards) {
          if (segs) st.text = [];
          // a tool result names its tool only through the call it answers (often an earlier item): the aligned
          // transcript row knows it (tool_name / "TOOL RESULT · name")
          var ar = r || {}, lm = /TOOL RESULT · (.+)$/.exec(ar.label || it.row_label || "");
          pane.appendChild(renderStructured(st, ar.tool_name || (lm && lm[1] !== "?" ? lm[1] : "")));
        }
      });
    }
    // Wire JSON: the whole request envelope as sent, opened along the path to the selected value, plus the response.
    function wireJSON(path, isResp, tok, it) {
      var c = S.comp, w = c.wire, up = S.which === "up" && w.has_upstream;
      var wh = up ? "up" : w.which === "hermes" ? "hermes" : "down";
      return part("part=request", wh).then(function (full) {
        if (S.tok !== tok) return;
        pane.innerHTML = (it ? itemHead(it) : "") + upstreamBar(w);
        var tools = document.createElement("div");
        tools.className = "mt-sec";
        var bDl = mkBtn("download request");
        bDl.onclick = function () { download(JSON.stringify(full, null, 2)); };
        tools.innerHTML = '<span class="mt-sect">call ' + esc(c.call_id) + " · " + num((w.meta || {}).req_bytes) + " bytes" + (up ? " · upstream (proxy → provider)" : "") + "</span>";
        tools.appendChild(bDl);
        pane.appendChild(tools);
        var resp = jsonPanel("response · parsed", w.response || {}, { open: isResp ? 2 : 0 });
        var req = jsonPanel("request" + (path ? " · " + path.join(".") : ""), full, { open: 1, path: isResp ? null : path, targetOpen: 3 });
        if (isResp) {
          pane.appendChild(resp);
          var s = document.createElement("div"), holder = document.createElement("div"), b = mkBtn("raw response events");
          s.className = "mt-sec"; s.appendChild(b);
          b.onclick = function () {
            api("/inspector/wire/part?id=" + encodeURIComponent(w.id) + "&part=response_raw").then(function (raw) {
              var events = raw.raw.split("\n").filter(function (l) { return l.indexOf("data:") === 0 || l.charAt(0) === "{"; }).map(function (l) {
                var t = l.indexOf("data:") === 0 ? l.slice(5).trim() : l;
                try { return JSON.parse(t); } catch (e) { return t; }
              });
              holder.innerHTML = "";
              holder.appendChild(jsonPanel("raw response events (" + events.length + ")", events, { open: 1 }));
            });
          };
          pane.append(s, holder, req);
        } else pane.append(req, resp);
        if (w.headers_down && Object.keys(w.headers_down).length) pane.appendChild(jsonPanel((w.has_upstream ? "downstream" : "request") + " headers (secrets redacted)", w.headers_down, { open: 0 }));
        if (w.has_upstream && w.headers_up && Object.keys(w.headers_up).length) pane.appendChild(jsonPanel("upstream headers (secrets redacted)", w.headers_up, { open: 0 }));
        var t = req.querySelector(".mtj-target");
        if (t && !isResp) scrollTo(t, "start");
      });
    }
    function respReadable(tok) {
      var c = S.comp, w = c.wire, p = w.response || {}, m = w.meta || {};
      var r = S.rows.filter(function (x) { return x.role === "assistant" && x.wire === c.call_id; }).pop();
      var html = '<div class="mti-msg k-assistant is-static"><div class="mti-h"><span class="mt-badge">MODEL OUTPUT</span><span class="mt-chip mt-dim">' + esc(c.call_id) +
        "</span>" + (p.finish ? '<span class="mt-chip">' + esc(p.finish) + "</span>" : "") + '<span class="mti-ts">' + shortT(m.ended) + "</span></div></div>" + callMeta(w);
      if (m.status == null) html += '<div class="mt-empty">Request sent; the response has not arrived yet.</div>';
      if (p.thinking) html += secH("💭 thinking (wire)", "mt-thinkh") + '<pre class="mt-pre mt-thinkpre">' + esc(p.thinking) + "</pre>";
      if (p.text) html += secH("text") + '<pre class="mt-pre">' + esc(p.text) + "</pre>";
      if (r) {
        var stored = (r.content || "").trim(), wire = (p.text || "").trim();
        html += '<div class="mti-chips">' + (stored === wire ? '<span class="mt-chip mt-wire">matches state.db row #' + r.id + "</span>"
          : '<span class="mt-chip mt-flip">state.db row #' + r.id + " differs (" + num(stored.length) + " vs " + num(wire.length) + " chars)</span>") +
          '<button type="button" class="mt-link" data-a="torow" data-row="' + r.id + '">row #' + r.id + " →</button></div>";
      }
      pane.innerHTML = html;
      var calls = (p.tool_calls || []).map(function (t) { return { name: t.name, id: t.id, args: t.args }; });
      if (calls.length) pane.appendChild(renderStructured({ thinking: [], text: [], calls: calls, results: [] }));
      if (p.usage) pane.appendChild(jsonPanel("usage (wire)", p.usage, { open: 2, quiet: true }));
      return null;
    }
    function gotoRow(rowId) {
      S.mode = "transcript";
      store("mode", S.mode);
      renderMode();
      var find = function () { return S.rows.findIndex(function (r) { return String(r.id) === String(rowId); }); };
      var go = function () {
        var i = find();
        renderTL(false);
        if (i >= 0) select(i, true);
      };
      if (find() >= 0) go(); else openSession(S.sid, rowId);
    }
    function setMode(mode) {
      hpop.close();  // a popover never outlives the view it explains
      if (mode === S.mode) return;
      S.mode = mode;
      store("mode", mode);
      renderMode();
      if (mode === "wire") {
        S.detail = S.csel ? "citem" : "row";
        if (!S.comp || S.comp.session.id !== S.sid) { S.comp = null; renderTL(true); loadCompiled(); } else renderTL(true);
      } else { S.detail = "row"; renderTL(true); }
      if (!mm(MOBILE_Q)) renderDetail();
    }
    function renderTL(scrollEnd) {
      schedLive();
      if (S.mode === "wire") return renderCompiled(scrollEnd);
      var atEnd = nearEnd();
      var html = '<div class="mti-legend">' + LEGEND.map(function (x) { return '<span class="mt-badge k-' + x[0] + '">' + x[1] + "</span>"; }).join("") + "</div>";
      if (S.older) html += '<div class="mti-turn"><button type="button" class="mt-btn" data-a="older">load older (before #' + S.older + ")</button></div>";
      S.rows.forEach(function (r, i) {
        if (TRIG[r.kind]) html += '<div class="mti-turn"><span>turn · ' + esc(r.label) + " · " + shortT(r.timestamp) + "</span></div>";
        if (visible(r)) html += rowHTML(r, i);
      });
      tl.innerHTML = html || '<div class="mt-empty">no rows</div>';
      if (scrollEnd && (atEnd || S.firstPaint !== S.sid)) {
        if (mm(MOBILE_Q)) {
          if (S.firstPaint !== S.sid) { var last = tl.lastElementChild; if (last) last.scrollIntoView({ block: "end" }); }
        } else tl.scrollTop = tl.scrollHeight;
        S.firstPaint = S.sid;
      }
    }
    function select(i, scroll, noSheet) {
      if (i < 0 || i >= S.rows.length) return;
      S.sel = i;
      S.detail = "row";
      $$(".mti-msg.is-sel").forEach(function (e) { e.classList.remove("is-sel"); });
      var el = root.querySelector('.mti-tl .mti-msg[data-i="' + i + '"]');
      if (el) { el.classList.add("is-sel"); if (scroll) scrollTo(el, "nearest"); }
      if (mm(MOBILE_Q) && !noSheet) setSheet(true);
      renderDetail();
    }
    function step(d) {
      var i = S.sel;
      do { i += d; } while (i >= 0 && i < S.rows.length && !visible(S.rows[i]));
      if (i >= 0 && i < S.rows.length) select(i, true, true);
    }

    // detail: two tabs per mode (TTABS for transcript rows, WTABS for wire items)
    function renderTabs(list, cur) {
      $(".mti-tabs").innerHTML = list.map(function (t, i) {
        return '<button type="button" class="mt-tab' + (cur === t[0] ? " is-on" : "") + '" data-t="' + t[0] + '" title="' + esc(t[2]) + '"><kbd>' + (i + 1) + "</kbd>" + t[1] + "</button>";
      }).join("");
      var d = list.filter(function (t) { return t[0] === cur; })[0];
      $(".mti-tabhint").textContent = d ? d[2] : "";
    }
    function setTab(t) {
      hpop.close();
      if (S.mode === "wire" && S.detail === "citem") { S.tabW = t === "json" ? "json" : "readable"; store("dtabW", S.tabW); }
      else { S.tabT = t === "row" ? "row" : "readable"; store("dtabT", S.tabT); }
      renderDetail();
    }
    function fullRow(id) {
      if (S.rowCache[id]) return Promise.resolve(S.rowCache[id]);
      return api("/inspector/row?id=" + id).then(function (d) { S.rowCache[id] = d; return d; });
    }
    // the call a row is on: a reply → the call that produced it; anything else → the first request that carried it
    function wireFor(r) {
      if (r.role === "assistant") return r.wire ? { call: r.wire } : null;
      if (r.framing && r.framing.first) return { call: r.framing.first.call, item: r.framing.first.i };
      if (r.framing && r.framing.latest) return { call: r.framing.latest.call, item: r.framing.latest.i };
      var i = S.rows.indexOf(r);
      for (var j = i + 1; j < S.rows.length; j++) if (S.rows[j].role === "assistant" && S.rows[j].wire) return { call: S.rows[j].wire, locate: true };
      return null;
    }
    function headerCard(r) {
      return '<div class="mti-msg k-' + (r.kind || r.role) + ' is-static"><div class="mti-h"><span class="mt-badge">' + esc(r.label) +
        '</span><span class="mt-chip mt-dim">#' + r.id + "</span>" + frChips(r) + '<span class="mti-ts">' + shortT(r.timestamp) + "</span></div>" +
        (r.flags || []).map(function (x) { return '<div class="mt-flag">⚠ ' + esc(x) + "</div>"; }).join("") + "</div>";
    }
    function kv(pairs) {
      return '<div class="mt-kv">' + pairs.filter(Boolean).map(function (p) { return "<b>" + esc(p[0]) + "</b><span>" + p[1] + "</span>"; }).join("") + "</div>";
    }
    function renderDetail() {
      renderRef();
      if (S.mode === "wire" && S.detail === "citem" && S.csel) {
        pane.innerHTML = '<div class="mt-empty">loading…</div>';
        var ctok = ++S.tok;
        Promise.resolve().then(function () { return renderCompiledDetail(ctok); }).catch(function (e) {
          if (S.tok === ctok) pane.innerHTML = '<div class="mt-empty mt-bad">' + esc(e.message || e) + "</div>";
        });
        return;
      }
      var r = S.rows[S.sel];
      if (!r || (S.mode === "wire" && S.detail !== "row")) {
        renderTabs(S.mode === "wire" ? WTABS : TTABS, S.mode === "wire" ? S.tabW : S.tabT);
        pane.innerHTML = '<div class="mt-empty">' + (S.mode === "wire" ? "Select an item of the request." : "Select a message.") + "</div>";
        return;
      }
      renderTabs(TTABS, S.tabT);
      pane.innerHTML = '<div class="mt-empty">loading…</div>';
      var tok = ++S.tok;
      Promise.resolve().then(function () { return (S.tabT === "row" ? tabRow : tabReadable)(r, tok); }).catch(function (e) {
        if (S.tok === tok) pane.innerHTML = '<div class="mt-empty mt-bad">' + esc(e.message || e) + "</div>";
      });
    }
    // Transcript › Readable: exactly what state.db persisted for the row, nothing the wire added.
    function tabReadable(r, tok) {
      return fullRow(r.id).then(function (fr) {
        if (S.tok !== tok) return;
        var row = fr.row || {}, fm = r.framing || {}, pv = fr.provenance || {}, parts = fr.parts || null, wf = wireFor(r), html = headerCard(r);
        if (row.role === "assistant") {
          var rs = row.reasoning_content || row.reasoning;
          if (rs) html += secH("💭 thinking · " + num(rs.length) + " chars", "mt-thinkh") + '<pre class="mt-pre mt-thinkpre">' + esc(rs) + "</pre>";
          if (row.content) html += '<pre class="mt-pre">' + esc(row.content) + "</pre>";
          else if (!(row.tool_calls && row.tool_calls.length)) html += '<div class="mt-dim mt-hint">(empty content)</div>';
        } else if (row.role !== "tool") {
          var authored = (parts || []).filter(function (p) { return p.type === "human" || p.type === "system_event"; });
          if (authored.length) {
            authored.forEach(function (p) {
              var o = p.origin || {};
              if (authored.length > 1 || p.type === "system_event") {
                html += secH(p.type === "human" ? "human · " + (p.delivery || "turn") + (o.platform ? " · " + o.platform : "") : "system_event · " + (p.kind || "?"));
              }
              html += '<pre class="mt-pre">' + esc(p.text || "") + "</pre>";
            });
          } else html += '<pre class="mt-pre">' + esc(row.content || "") + "</pre>";
          (parts || []).forEach(function (p) {
            if (p.type === "media") html += kv([["media", esc(p.mime || "?") + " · " + esc(p.path || "") + ' <span class="mt-dim">' + esc(String(p.sha256 || "").slice(0, 12)) + "</span>"]]);
            if (p.type === "injection") {
              html += '<details class="mti-persist"><summary><span class="mt-chip mt-inj">+' + esc(p.kind || "injection") + "</span> persisted injection part · " + num((p.text || "").length) +
                " chars — rendered into the wire at send time</summary><div class=\"mt-injblk\">" + esc(p.text || "") + "</div></details>";
            }
          });
          if (fr.parts_consistent === false) html += '<div class="mti-chips"><span class="mt-chip mt-flip">content ≠ plain view of parts</span></div>';
        }
        if (row.api_content && row.api_content !== row.content) {
          var inj = fr.inject || {};
          html += '<details class="mti-persist"><summary><span class="mt-chip mt-inj">api_content</span> persisted send-time copy · ' + num(row.api_content.length) + " chars" +
            (inj.identical_core ? " (content + " + num(row.api_content.length - (row.content || "").length) + " wrapper chars" + (inj.blocks && inj.blocks.length ? ": " + inj.blocks.map(esc).join(", ") : "") + ")" : " — rewrites the body") +
            '</summary><pre class="mt-pre">' + hiInjected(row.api_content) + "</pre></details>";
        }
        if (wf) {
          html += '<div class="mti-onwire"><button type="button" class="mt-btn mt-mini" data-a="towire" data-row="' + r.id + '"' + (row.role === "assistant" ? ' data-resp="1"' : "") + ">" +
            (row.role === "assistant" ? "model output on the wire" : "on the wire") + " → call " + esc(shortId(wf.call)) + "</button></div>";
        }
        html += '<details class="mti-prov"><summary>provenance</summary>' + kv([
          ["role", esc(row.role)], ["true nature", esc((fr["class"] || {}).label)],
          ["classified from", (fr["class"] || {}).typed ? "typed columns (sender_kind / parts_json)" : row.role === "user" ? "text heuristics (untyped row)" : "role"],
          ["display_kind", esc(row.display_kind || "—")]].concat(PROV.filter(function (k) { return pv[k] != null; }).map(function (k) {
            return [k, k === "sent_at" ? esc(fmtT(pv[k])) + ' <span class="mt-dim">(' + esc(pv[k]) + ")</span>" : esc(pv[k])];
          })).concat([
          ["platform_message_id", esc(row.platform_message_id || "—")], ["active / compacted", row.active + " / " + row.compacted],
          ["message_uid", esc(row.message_uid || "—")], ["finish_reason", esc(row.finish_reason || "—")],
          ["tool_call_id", esc(row.tool_call_id || "—")], ["wire", r.wire ? esc(r.wire) : row.role === "assistant" ? "not captured" : "—"],
          fm.first ? ["first send", esc(fm.first.framing) + " · call " + esc(fm.first.call) + " · item " + fm.first.i + "/" + fm.first.of] : null,
          fm.latest ? ["latest replay", esc(fm.latest.framing) + " · call " + esc(fm.latest.call) + " · item " + fm.latest.i + "/" + fm.latest.of] : null])) + "</details>";
        pane.innerHTML = html;
        var at = pane.querySelector(".mti-onwire") || pane.querySelector(".mti-prov");
        if (row.role === "assistant" && Array.isArray(row.tool_calls) && row.tool_calls.length) {
          pane.insertBefore(renderStructured({ thinking: [], text: [], results: [], calls: row.tool_calls.map(function (t) {
            var fn = t["function"] || {}, a = fn.arguments != null ? fn.arguments : t.arguments;
            return { name: fn.name || t.name, id: t.id || t.call_id, args: a };
          }) }), at);
        }
        if (row.role === "tool") {
          pane.insertBefore(renderStructured({ thinking: [], text: [], calls: [], results: [{ name: row.tool_name, id: row.tool_call_id, output: row.content }] }, row.tool_name), at);
        }
        if (row.display_metadata && typeof row.display_metadata === "object") pane.querySelector(".mti-prov").appendChild(jsonPanel("display_metadata", row.display_metadata, { open: 1, quiet: true }));
      });
    }
    function hiInjected(text) {
      // XML-style wrapper blocks (any tag) and Hermes's bracketed envelope lines
      var s = esc(text);
      [/&lt;([A-Za-z][\w:-]{1,48})\b[\s\S]*?&lt;\/\1&gt;/g,
        /\[Triggering message id:[^\]]*\]/g, /^\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d\d-\d\d \d\d:\d\d(:\d\d)? [A-Z]{2,5}\]/gm,
        /\[OUT-OF-BAND USER MESSAGE[^\]]*\]/g, /\[System: This conversation[\s\S]*?(?=\n\n|$)/g].forEach(function (rx) {
        s = s.replace(rx, function (m) { return '<mark class="mt-inj">' + m + "</mark>"; });
      });
      return s;
    }
    function tabRow(r, tok) {
      return fullRow(r.id).then(function (fr) {
        if (S.tok !== tok) return;
        pane.innerHTML = headerCard(r);
        pane.appendChild(jsonPanel("messages row (exact SQLite columns; JSON columns parsed)", fr.row, { open: 1 }));
      });
    }
    function callMeta(w) {
      var c = w.call || {}, m = w.meta || {};
      var src = m.source === "hermes" ? "Hermes hook · " + (m.exact !== 0 ? "exact request" : m.tools_exact === 1 ? "parameters from hook copy" : "envelope from hook copy") : (m.source === "proxy" ? "proxy log" : esc(m.source || "—"));
      return kv([["call", esc(w.id) + " · " + esc(m.family) + " · " + esc(m.model) + " · " + (m.status == null ? "in flight" : "HTTP " + esc(m.status))],
        ["captured by", src + (m.file ? " · proxy file " + esc(m.file) : "")],
        ["timing", fmtT(m.started) + (c.total_s != null ? " · " + c.total_s + "s total" : "") + (c.ttfb_s != null ? " · ttfb " + c.ttfb_s + "s" : "") + (c.retry_s ? " · retry " + c.retry_s + "s" : "")],
        ["tokens", "prompt " + num(c.prompt_tokens) + " · cached " + num(c.cached_tokens) + " (" + (c.hit_pct == null ? "—" : c.hit_pct) + "%) · out " + num(c.output_tokens) + " · think " + num(c.thinking_tokens)],
        ["route", esc(c.provider || c.auth_label || "—") + (c.auth_key ? " · key " + esc(mk(c.auth_key)) + " " + esc(c.project || "") : "") + " · attempts " + (c.attempts == null ? "—" : c.attempts) + " · 429s " + (c.n429 == null ? "—" : c.n429)],
        ["request", num(m.req_bytes) + " bytes · " + num(m.n_items) + " items" + (w.upstream_differs ? " · upstream differs" : "")]]);
    }
    function upstreamBar(w) {
      // downstream = what Hermes sent; upstream = what a proxy sent the provider (only when proxy logs are merged)
      if (!w.has_upstream) return "";
      return '<div class="mt-sec"><span class="mt-sect">leg</span><div class="mt-tools"><button type="button" class="mt-tab mti-which' + (S.which === "up" ? " is-on" : "") +
        '" data-a="which" title="downstream = what Hermes sent; upstream = what the proxy sent the provider">' + (S.which === "up" ? "↑ upstream (proxy → provider)" : "↓ downstream (client → proxy, post-adapter)") + "</button></div></div>";
    }
    // events
    function onClick(e) {
      var a = e.target.closest("[data-a]");
      if (a && inScope(a)) {
        var act = a.dataset.a;
        if (act === "sb") {
          if (mm(WIDE_Q)) { box.classList.toggle("mti-nosb"); store("nosb", box.classList.contains("mti-nosb")); }
          else setDrawer(!box.classList.contains("mti-sb-open"));
        } else if (act === "sbclose" || act === "scrim") setDrawer(false);
        else if (act === "back") setSheet(false);
        else if (act === "older") loadRows(true);
        else if (act === "which") { S.which = S.which === "up" ? "down" : "up"; renderDetail(); }
        else if (act === "clayer") { S.clayer = S.clayer === "hermes" ? "wire" : "hermes"; S.partCache = {}; S.comp = null; S.csel = null; renderTL(false); loadCompiled(); }
        else if (act === "torow") { setSheet(false); gotoRow(a.dataset.row); }
        else if (act === "towire") {
          var tr = S.rows.filter(function (x) { return String(x.id) === String(a.dataset.row); })[0];
          rowToWire(tr, a.dataset.kind || null, !!a.dataset.resp);
        }
        else if (act === "cprev") stepCall(-1);
        else if (act === "cnext") stepCall(1);
        else if (act === "clatest") { if (S.comp) setCall(S.comp.latest_call); }
        else if (act === "fhelp") hpop.toggle();
        else if (act === "copyref") copyFrom(a, currentRef());
        else if (act === "copysid") copyFrom(a, S.sid);
        else if (act === "after") { var af = tl.querySelector(".mti-after"); if (af) scrollTo(af, "start"); }
        return;
      }
      var md = e.target.closest("[data-mode]");
      if (md && inScope(md)) { setMode(md.dataset.mode); return; }
      var ci = e.target.closest("[data-ci]");
      if (ci && inScope(ci)) {
        if (ci.classList.contains("mti-msg") && S.csel === ci.dataset.ci && S.detail === "citem" && !mm(MOBILE_Q)) ci.classList.toggle("is-exp");
        selectC(ci.dataset.ci, false);
        return;
      }
      var t = e.target.closest(".mt-tab[data-t]");
      if (t && inScope(t)) { setTab(t.dataset.t); return; }
      var ses = e.target.closest(".mti-ses");
      if (ses) { openSession(ses.dataset.id); return; }
      var msg = e.target.closest(".mti-tl .mti-msg[data-i]");
      if (msg) {
        var i = +msg.dataset.i;
        if (i === S.sel && !mm(MOBILE_Q)) msg.classList.toggle("is-exp");
        select(i, false);
      }
    }
    function inScope(el) { return root.contains(el) || layer.contains(el); }
    function onKey(e) {
      if (!root.isConnected || typing(e) || e.metaKey || e.ctrlKey || e.altKey) return;
      var k = e.key;
      if ((k === "Enter" || k === " ") && onControl(e)) return;
      if (k === "j") { if (S.mode === "wire") stepC(1); else step(1); }
      else if (k === "k") { if (S.mode === "wire") stepC(-1); else step(-1); }
      else if (k === "c" || k === "w") setMode("wire");
      else if (k === "t") setMode("transcript");
      else if (k === "[" && S.mode === "wire") stepCall(-1);
      else if (k === "]" && S.mode === "wire") stepCall(1);
      else if (k === "Enter") { var el = root.querySelector(".mti-tl .mti-msg.is-sel"); if (el) el.classList.toggle("is-exp"); }
      else if (k === "1" || k === "2") { var tb = $$(".mti-tabs .mt-tab[data-t]")[+k - 1]; if (tb) setTab(tb.dataset.t); }
      else if (k === "/") $(".mti-q").focus();
      else if (k === "s") $('[data-a="sb"]').click();
      else if (k === "f") { var fl = $('[data-f="flag"]'), al = $('[data-rows="all"]'); (fl.checked ? al : fl).checked = true; renderTL(); }
      else if (k === "G") select(S.rows.length - 1, true, true);
      else if (k === "r") { loadRows(false); if (S.mode === "wire") loadCompiled(); }
      else if (k === "Escape") { setSheet(false); setDrawer(false); }
      else return;
      e.preventDefault();
    }
    root.addEventListener("click", onClick);
    layer.addEventListener("click", onClick);
    // A truncated session name glides once to its end while hovered (about 45 px/s after a short pause, measured from
    // how far it overflows) and eases back on leave. Mouse/pen only, never without overflow, never with reduced motion.
    var RM = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
    function mqStart(el) {
      if (RM.matches) return;
      var m = el.__mq, over = m ? m.over : el.scrollWidth - el.clientWidth;
      if (over <= 2) return;
      if (!m) {
        var sp = document.createElement("span");
        sp.className = "mt-mq";
        m = el.__mq = { txt: el.textContent, s: sp, over: over };
        sp.textContent = m.txt;
        el.textContent = "";
        el.appendChild(sp);
        el.classList.add("is-mq");
        void sp.offsetWidth;  // start from the resting position
      }
      var d = m.over + 8, t = Math.max(1.2, d / 45);
      m.s.style.transition = "transform " + t.toFixed(2) + "s linear .5s";
      m.s.style.transform = "translateX(" + (-d) + "px)";
    }
    function mqStop(el) {
      var m = el.__mq;
      if (!m) return;
      if (!m.s.isConnected || m.s.parentNode !== el) { el.__mq = null; el.classList.remove("is-mq"); return; }  // re-rendered meanwhile
      m.s.style.transition = "transform .35s ease-out";
      m.s.style.transform = "translateX(0)";
      var done = function () {
        if (el.__mq !== m || m.s.style.transform !== "translateX(0)") return;  // hovered again before it settled
        el.__mq = null; el.classList.remove("is-mq");
        if (m.s.parentNode === el) el.textContent = m.txt;  // plain text again: the ellipsis comes back
      };
      m.s.addEventListener("transitionend", done, { once: true });
      setTimeout(done, 450);
    }
    function mqOver(e) {
      if (e.pointerType && e.pointerType !== "mouse" && e.pointerType !== "pen") return;
      var el = e.target.closest && e.target.closest(".mti-st, .mti-sid");
      if (el && inScope(el)) mqStart(el);
    }
    function mqOut(e) {
      var el = e.target.closest && e.target.closest(".mti-st, .mti-sid");
      if (el && !(e.relatedTarget && el.contains(e.relatedTarget))) mqStop(el);
    }
    root.addEventListener("pointerover", mqOver);
    layer.addEventListener("pointerover", mqOver);
    root.addEventListener("pointerout", mqOut);
    layer.addEventListener("pointerout", mqOut);
    document.addEventListener("keydown", onKey);
    place();
    if (window.ResizeObserver) {
      ro = new ResizeObserver(schedFit);
      [root.querySelector(".mti-top"), root.querySelector(".mti-gauge"), root.parentElement, clipParent(body)].forEach(function (el) { if (el) ro.observe(el); });
    }
    window.addEventListener("resize", schedFit);
    schedFit();
    $('[data-f="tools"]').onchange = function () { renderTL(); };
    $('[data-f="flag"]').onchange = $('[data-rows="all"]').onchange = function () { renderTL(); };
    $('[data-f="inactive"]').onchange = function () {
      if (S.mode === "wire") { S.rows = []; S.older = null; loadRows(false); } else openSession(S.sid);
    };
    $('[data-f="live"]').onchange = schedLive;
    document.addEventListener("scroll", schedLive, true);
    $(".mti-q").oninput = function () { renderTL(); };
    $(".mti-sq").oninput = function () { clearTimeout(sesT); sesT = setTimeout(loadSessions, 250); };
    root.querySelector(".mti-callsel").onchange = function (e) { setCall(e.target.value); };
    var mq = window.matchMedia(MOBILE_Q), mqw = window.matchMedia(WIDE_Q);
    var onMQ = function () { hpop.close(); setSheet(false); setDrawer(false); place(); };
    if (mq.addEventListener) { mq.addEventListener("change", onMQ); mqw.addEventListener("change", onMQ); }
    var timer = setInterval(function () {
      schedLive();
      if (!(f("live") && S.sid && !document.hidden && nearEnd() && !box.classList.contains("mti-det-open"))) return;
      if (S.mode === "wire") loadCompiled(true); else if (!S.loading) loadRows(false, null, true);
    }, 8000);

    renderMode();
    loadSessions().then(function () { return openSession(init.session || S.main || S.fallback || "", init.row); });

    return function () {
      S.alive = false;
      clearInterval(timer);
      clearTimeout(sesT);
      document.removeEventListener("keydown", onKey);
      root.removeEventListener("click", onClick);
      root.removeEventListener("pointerover", mqOver);
      root.removeEventListener("pointerout", mqOut);
      if (mq.removeEventListener) { mq.removeEventListener("change", onMQ); mqw.removeEventListener("change", onMQ); }
      document.documentElement.classList.remove("mt-lock");
      document.removeEventListener("scroll", schedJump, true);
      window.removeEventListener("resize", schedJump);
      if (jumpRaf) cancelAnimationFrame(jumpRaf);
      if (fitRaf) cancelAnimationFrame(fitRaf);
      if (ro) ro.disconnect();
      window.removeEventListener("resize", schedFit);
      document.removeEventListener("scroll", schedLive, true);
      if (liveRaf) cancelAnimationFrame(liveRaf);
      hpop.close(); hpop.destroy();
      layer.remove();
    };
  }

  // ───────────────────────── Model Call Telemetry ─────────────────────────
  // Family tabs come from the data: All, every family in the window (stable order, see orderFams), then Sessions.
  // Calls tab bar: All | a scrollable strip of model families | divider | Sessions (a different view, not a family).
  // All and Sessions never scroll away; the strip shows edge fades only where there is more to scroll.
  var TABS_SKELETON = '<div class="mtt-tablist" role="tablist" aria-label="Model family">' +
    '<button type="button" class="mt-tab mtt-pin" role="tab" data-t="all" title="Every model family">All</button>' +
    '<div class="mtt-fstrip" role="none"></div><span class="mtt-tabsep" aria-hidden="true"></span>' +
    '<button type="button" class="mt-tab mtt-tab-view mtt-pin" role="tab" data-t="sessions" title="Per-session totals: a different view, not a family">Sessions</button></div>';
  var COLS = [["started", "time", "l"], ["lane", "lane", "l"], ["model", "model", "l"], ["auth_key", "key", "l"], ["attempts", "att"], ["errors", "errors", "l"],
    ["retry_s", "retry"], ["ttfb_s", "ttfb"], ["gen_s", "gen"], ["total_s", "total"], ["prompt_tokens", "prompt"], ["cached_tokens", "cached"],
    ["hit_pct", "hit"], ["cache_write_tokens", "write"], ["output_tokens", "out"], ["thinking_tokens", "think"], ["cost_usd", "cost"],
    ["cost_equiv_usd", "equiv"], ["aff", "affinity", "l"], ["diverge", "why miss", "l"]];
  var M = '<span class="mt-dim">—</span>';
  // General call errors. Unit = one stored call: never a user turn. "observations" are the failure events stored for
  // the call (retries, rotations, fallbacks — not a deduplicated count of physical attempts). No status = unknown
  // (in flight, interrupted or uncaptured), never a failure. Only status/category/count are shown: no error text.
  var ERR_HELP = "Per call, not per turn. failed = no successful response; recovered = succeeded after recorded failures " +
    "(retry, key rotation or fallback); no status = in flight, interrupted or not captured. Observations are stored failure " +
    "events, not a deduplicated attempt count.";
  var ERR_CAT = { authentication: "auth", permission: "permission", rate_limit: "rate limit", server: "server", http: "HTTP",
    transport_or_invalid_response: "transport / invalid response" };
  // column-head tooltips (the legend that used to sit under the table)
  var COL_TIPS = {
    errors: ERR_HELP + " Sorts failed first, then recovered, then by failure observations; rate limits (429) show inside each chip.",
    auth_key: "Provider of the serving attempt, or a credential label when a store has one",
    attempts: "Attempts Hermes made for this call", cached_tokens: "Provider-reported cache-read tokens",
    hit_pct: "hit = cached ÷ prompt; a miss is prompt > 20k and hit < 50%", cost_usd: "Hermes's list-price estimate; subscription routes show $0",
    cost_equiv_usd: "API-equivalent cost of subscription routes", aff: "Key affinity across the session's calls, when a store has credential labels",
    diverge: "Why the prompt cache missed: the first change from the previous comparable request",
  };
  function errOf(r) {
    var e = r.error_summary;
    if (e && typeof e === "object" && e.outcome) return e;
    var st = typeof r.status === "number" ? r.status : null, nf = r.nfail;
    var failed = st != null && !(st >= 200 && st < 300), ok = st != null && st >= 200 && st < 300;
    return { v: 0, scope: "call", outcome: failed ? "failed" : ok ? "succeeded" : "unknown",
      category: !failed ? null : st === 0 ? "transport_or_invalid_response" : st === 401 ? "authentication" : st === 403 ? "permission"
        : st === 429 ? "rate_limit" : st >= 500 ? "server" : "http",
      affected: failed || nf > 0, recovered: ok && nf > 0, recorded_failure_observations: nf == null ? null : nf };
  }
  function obsText(n) { return n == null ? "" : n + " failure observation" + (n === 1 ? "" : "s"); }
  function errChip(r) {
    var e = errOf(r), n = e.recorded_failure_observations, st = r.status;
    if (e.outcome === "failed") {
      var lab = ERR_CAT[e.category] || "error", code = typeof st === "number" && st > 0 ? " " + st : "";
      return '<span class="mt-chip mt-flip mtt-err" title="This call ended without a successful response' + (n ? " · " + obsText(n) : "") +
        ' (per call, not per turn)">failed · ' + esc(lab) + code + "</span>";
    }
    if (e.recovered) {
      return '<span class="mt-chip mt-warnc mtt-err" title="Succeeded after ' + esc(obsText(n)) + (r.n429 ? ", " + r.n429 + " of them rate limits (429)" : "") +
        ' (retry, key rotation or fallback — mechanism not recorded). Observations are not a deduplicated attempt count.">recovered · ' +
        (n == null ? "?" : n) + " obs" + (r.n429 ? " · 429" : "") + "</span>";
    }
    if (e.outcome === "unknown") {
      if (st != null && st !== "") {  // a non-HTTP code an SDK reported: bounded and escaped, outcome still unknown
        return '<span class="mt-chip mt-dim mtt-err" title="Non-HTTP status code reported for this call; outcome unknown">code ' + esc(String(st).slice(0, 40)) + "</span>";
      }
      return '<span class="mt-chip mt-dim mtt-err" title="No final status recorded: in flight, interrupted or not captured. Not counted as a failure.">no status</span>';
    }
    return "";
  }
  function errDetail(r) {
    var e = errOf(r), n = e.recorded_failure_observations;
    if (!e.affected && e.outcome !== "unknown") return "";
    var what = e.outcome === "failed" ? "failed · " + (ERR_CAT[e.category] || "error") + (typeof r.status === "number" && r.status > 0 ? " (HTTP " + r.status + ")" : "")
      : e.recovered ? "succeeded after recorded failures" : e.outcome === "unknown" ? "unknown — no final status (in flight, interrupted or not captured)" : "succeeded";
    return '<div class="mtt-errsum"><span><i>outcome</i> <b class="' + (e.outcome === "failed" ? "mt-bad" : e.recovered ? "mt-warn" : "mt-dim") + '">' + esc(what) + "</b></span>" +
      (n != null ? "<span><i>failure observations</i> " + n + ' <span class="mt-dim">(stored events, not deduplicated attempts)</span></span>' : "") +
      (r.n429 ? "<span><i>429s</i> " + r.n429 + "</span>" : "") + '<span class="mt-dim">scope: this call, not a conversation turn · evidence: transport details below</span></div>';
  }
  // account labels are often email addresses: never put one on screen (the collector masks them too)
  var mk = function (v) { return v == null ? v : String(v).replace(/([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*?)([A-Za-z0-9._%+-])?@([A-Za-z0-9-])[A-Za-z0-9.-]*?(\.[A-Za-z]{2,})\b/g, function (m, a, b, c, d, t) { return a + "***" + (c || "") + "@" + d + "***" + t; }); };
  var kk = function (n) { return n == null ? M : (n >= 1e6 ? (n / 1e6).toFixed(2) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n)); };
  var sec = function (s) { return s == null ? M : (s >= 100 ? s.toFixed(0) : s >= 10 ? s.toFixed(1) : s.toFixed(2)); };
  var usd = function (x) { return x == null ? M : x === 0 ? "$0" : x < 0.01 ? "$" + x.toFixed(4) : "$" + x.toFixed(x < 1 ? 3 : 2); };
  var tm = function (t) { return new Date(t * 1000).toLocaleTimeString([], { hour12: false }); };
  var dt = function (t) { var d = new Date(t * 1000); return (d.toDateString() === new Date().toDateString() ? "" : (d.getMonth() + 1) + "/" + d.getDate() + " ") + tm(t); };
  function hitColor(x) { return x == null ? "var(--mt-muted)" : x >= 90 ? "var(--mt-good)" : x >= 70 ? "var(--mt-lime)" : x >= 50 ? "var(--mt-warn)" : "var(--mt-bad)"; }
  function quant(arr, q) { if (!arr.length) return null; var s = arr.slice().sort(function (a, b) { return a - b; }); return s[Math.min(s.length - 1, Math.floor(q * s.length))]; }
  function hitHTML(x) {
    return '<span class="mtt-hitv" style="color:' + hitColor(x) + '">' + (x == null ? "—" : x.toFixed(1) + "%") + '</span><span class="mtt-hb"><i style="width:' + (x || 0) + "%;background:" + hitColor(x) + '"></i></span>';
  }

  // What the Calls header last showed (family tabs, context gauge, family cards), kept across remounts: the tab's
  // ↻ reload rebuilds the view, and starting these empty would collapse them and shove the list up and back down.
  var KEPT = {};
  function mountTelemetry(root, init) {
    init = init || {};
    // provider is not a toolbar filter (it competed with the model-family tabs); a stored one would filter invisibly
    var T = { selectedSession: init.session || null, context: null, tab: store("ttab") || "all", prov: "", data: null, fams: null, provs: null, sess: null, sel: 0, open: {},
      sortKey: "started", sortDir: -1, lastOk: 0, alive: true };
    // Toolbar grammar shared with the Inspector: row 1 = model-family tabs (All and Sessions pinned, families in a
    // stable, scrollable strip between them); row 2 = labelled filters, help, auto-refresh. All visible. Freshness is the
    // page header's job (capture ago): the stamp only carries a fetch error.
    root.innerHTML =
      '<div class="mtt">' +
      '<div class="mtt-controls"><div class="mtt-tabs">' + TABS_SKELETON + '</div><span class="mtt-stamp mt-dim"></span></div>' +
      '<div class="mti-filters mtt-filters" role="toolbar" aria-label="Call filters">' +
      '<input type="search" class="mt-input mtt-sessq" data-c="sess" placeholder="session id" aria-label="Session id" title="Only calls of this session (exact id)">' +
      '<div class="mti-fpanel mtt-fpanel" role="group" aria-label="Filters">' +
      '<label class="mt-field" title="How far back to list calls"><span class="mt-flabel">window</span><select class="mt-input mtt-selw" data-c="hours" aria-label="Window">' +
      '<option value="1">1 h</option><option value="6" selected>6 h</option><option value="24">24 h</option><option value="72">72 h</option><option value="168">7 d</option></select></label>' +

      '<label class="mt-field" title="' + esc(ERR_HELP + " Calls without a final status are not errors.") + '"><span class="mt-flabel">errors</span><select class="mt-input mtt-sele" data-c="errs" aria-label="Errors">' +
      '<option value="">all calls</option><option value="any">any error</option><option value="failed">failed calls</option><option value="recovered">recovered</option></select></label>' +
      '<div class="mt-fgroup" role="group" aria-label="Only"><span class="mt-flabel" aria-hidden="true">only</span>' +
      '<label class="mt-tog" title="Prompt over 20k tokens with a cache hit under 50% (m)"><input type="checkbox" data-c="misses">cache misses</label>' +
      '<label class="mt-tog" title="More than 30 seconds in total (s)"><input type="checkbox" data-c="slow">slow &gt;30s</label></div>' +
      "</div>" +
      helpBtnHTML("mtt-fhelp") +
      liveHTML("c", "auto", "Refresh about every 5 seconds", "mtt-live") +
      "</div>" +
      '<div class="mtt-gauge"></div><div class="mtt-strip"></div><div class="mtt-list"></div>' +
      '<div class="mt-pop mti-fhelp" id="mtt-fhelp" role="dialog" aria-label="What these controls do" tabindex="-1" hidden><dl>' +
      helpRow("tabs", "One tab per model family in the window. Scroll sideways when they do not fit.", "1–9, ← →") +
      helpRow("window, session id", "Which calls are listed.") +
      helpRow("errors", ERR_HELP) +
      helpRow("cache misses", "Prompt over 20k tokens with a cache hit under 50%.", "m") +
      helpRow("slow >30s", "More than 30 seconds in total.", "s") +
      helpRow("auto-refresh", "Refreshes about every 5 seconds. While a call is open or the list is scrolled it shows paused, and new calls wait.", "r") +
      helpRow("cached, hit", "Cache-read tokens the provider reported. Hit is cached divided by prompt.") +
      helpRow("cost, equiv", "Hermes's list-price estimate. Subscription calls show $0, with the API price under equiv.") +
      helpRow("key, att, affinity", "Provider or credential label, attempts and key affinity. Hook capture records the provider name and Hermes's own attempts.") +
      helpRow("rows", "j and k select a call, Enter expands it.") +
      "</dl></div></div>";
    var layer = document.createElement("div");
    layer.className = "mt-root mt-layer";
    document.body.appendChild(layer);
    var $ = function (s) { return root.querySelector(s); };
    var c = function (k) { return root.querySelector('[data-c="' + k + '"]'); };
    var fhelp = $(".mti-fhelp");
    layer.appendChild(fhelp);
    var hpop = anchoredPop($(".mti-help"), fhelp);
    var newfloat = document.createElement("div"); newfloat.className = "mtt-newfloat"; layer.appendChild(newfloat);
    function liveState() {
      if (!c("auto").checked) return "off";
      if (T.tab !== "sessions" && (T.pending || (T.data && reading()))) return "reading";
      return "live";
    }
    var liveRaf = 0;
    function schedLive() { if (!liveRaf) liveRaf = requestAnimationFrame(function () { liveRaf = 0; if (T.alive) setLive($(".mt-live"), liveState()); }); }
    var KEEP = [".mtt-tabs", ".mtt-gauge", ".mtt-strip"];
    if (KEPT.ctx && (!T.selectedSession || T.selectedSession === KEPT.ctx.id)) T.context = KEPT.ctx;  // same session: no placeholder gauge
    KEEP.forEach(function (sel) { if (KEPT[sel]) { setHTML($(sel), KEPT[sel]); if (sel === ".mtt-gauge") $(sel).classList.add("is-stale"); } });
    if (KEPT.fam) { T.famKey = KEPT.fam.key; T.famOrder = KEPT.fam.order.slice(); T.famLabels = Object.assign({}, KEPT.fam.labels); }
    function remember() {
      KEEP.forEach(function (sel) { var el = $(sel); if (el) KEPT[sel] = el.innerHTML; });
      if (T.context && T.context.ctx_window) KEPT.ctx = T.context;
      if (T.famOrder) KEPT.fam = { key: T.famKey, order: T.famOrder.slice(), labels: Object.assign({}, T.famLabels), x: strip() ? strip().scrollLeft : 0 };
    }

    // Families keep their order while you look: sorted by call count when the listed calls change (window, session,
    // provider), then newcomers are appended and nothing moves on a poll. A selected family that has no calls in the
    // window keeps its tab. There is no cap and no "Other" bucket: the strip scrolls instead.
    function orderFams(d) {
      var ks = (d.families || []).map(function (x) { return x.family; });
      var key = c("hours").value + "|" + c("sess").value.trim() + "|" + T.prov;
      T.famLabels = T.famLabels || {};
      (d.families || []).forEach(function (x) { T.famLabels[x.family] = x.label; });
      if (key !== T.famKey || !T.famOrder) { T.famKey = key; T.famOrder = ks; return; }
      var had = {};
      T.famOrder.forEach(function (k) { had[k] = 1; });
      T.famOrder = T.famOrder.filter(function (k) { return ks.indexOf(k) >= 0 || k === T.tab; }).concat(ks.filter(function (k) { return !had[k]; }));
    }
    function famList() {
      var by = {}, out = [];
      (T.fams || []).forEach(function (x) { by[x.family] = x; });
      var order = (T.famOrder || []).slice();
      if (T.tab !== "all" && T.tab !== "sessions" && order.indexOf(T.tab) < 0) order.push(T.tab);  // remembered, none in this window
      order.forEach(function (k) { out.push(by[k] || { family: k, label: (T.famLabels || {})[k] || k, n: 0 }); });
      return out;
    }
    function tabs() {
      return [["all", "All"]].concat(famList().map(function (x) { return [x.family, x.label, x.n]; })).concat([["sessions", "Sessions"]]);
    }
    function strip() { return $(".mtt-fstrip"); }
    function revealTab(b) {  // bring a tab fully into the strip's view, instantly; never scrolls the page
      var s = strip();
      if (!b || !s || !s.contains(b)) return;
      var pad = 24, l = b.offsetLeft, r = l + b.offsetWidth;
      if (l - pad < s.scrollLeft) s.scrollLeft = Math.max(0, l - pad);
      else if (r + pad > s.scrollLeft + s.clientWidth) s.scrollLeft = r + pad - s.clientWidth;
    }
    function fades() {
      var s = strip();
      if (!s) return;
      s.classList.toggle("is-l", s.scrollLeft > 1);
      s.classList.toggle("is-r", s.scrollLeft + s.clientWidth < s.scrollWidth - 1);
    }
    function renderTabs() {
      var box = $(".mtt-tabs");
      if (!strip()) { box.innerHTML = TABS_SKELETON; box.__html = null; }
      var s = strip(), x = s.scrollLeft, fa = document.activeElement, focusT = fa && s.contains(fa) && fa.dataset ? fa.dataset.t : null;
      setHTML(s, famList().map(function (t) {
        return '<button type="button" class="mt-tab" role="tab" data-t="' + esc(t.family) + '" title="' + esc(t.n ? t.n + " calls" : "no calls in this window") + '">' + esc(t.label) + "</button>";
      }).join(""));
      // a poll that changes a count rewrites the strip: keep keyboard focus on the same family
      if (focusT != null && !(document.activeElement && s.contains(document.activeElement))) {
        var again = s.querySelector('.mt-tab[data-t="' + (window.CSS && CSS.escape ? CSS.escape(focusT) : focusT) + '"]');
        if (again) { try { again.focus({ preventScroll: true }); } catch (e) { again.focus(); } }
      }
      box.querySelectorAll(".mt-tab[data-t]").forEach(function (b) {
        var on = b.dataset.t === T.tab;
        b.classList.toggle("is-on", on); b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1;
      });
      s.scrollLeft = T.reveal === "keep" && KEPT.fam && KEPT.fam.x != null ? KEPT.fam.x : x;
      if (T.reveal) { T.reveal = false; revealTab(box.querySelector(".mtt-fstrip .mt-tab.is-on")); }
      fades();
    }
    function pickTab(id) { hpop.close(); T.tab = id; store("ttab", T.tab); T.sel = 0; T.open = {}; T.reveal = true; load(); }
    function famParam() {
      return T.tab === "sessions" ? "all" : T.tab;
    }
    function reading() {
      // an expanded call, a scrolled list or an open detail: someone is reading — don't move it
      if (Object.keys(T.open).some(function (k) { return T.open[k]; })) return true;
      if (T.data && T.data.rows && T.data.rows.length > PAGE) return true;  // older pages loaded
      var tall = root.querySelector(".mtt-tall");
      return (tall && tall.scrollTop > 40) || (window.scrollY || 0) > 240;
    }
    function load(poll) {
      if (poll && T.inflight) return Promise.resolve();  // a timer tick never stacks on a load still in flight
      var g = T.gen = (T.gen || 0) + 1;  // only the newest load may apply its response
      T.inflight = true;
      var done = function () { if (g === T.gen) T.inflight = false; };
      T.same = false;
      if (!poll) renderTabs();
      var hrs = c("hours").value, s = c("sess").value.trim();
      var q = "/calls?hours=" + hrs + "&session=" + encodeURIComponent(s) + "&provider=" + encodeURIComponent(T.prov);
      T.lastQ = q;
      var keep = function (d) { if (g === T.gen) { orderFams(d); T.fams = d.families || []; T.provs = d.providers || []; } return d; };
      var p = T.tab === "sessions"
        ? Promise.all([api("/sessions?hours=" + hrs), api(q + "&family=all&limit=1").then(keep)]).then(function (r) { if (g === T.gen) T.sess = r[0]; })
        : api(q + "&family=" + encodeURIComponent(famParam()) + listQuery() + (poll && T.data && T.data.rev ? "&rev=" + encodeURIComponent(T.data.rev) : "")).then(function (d) {
          if (g !== T.gen) return;
          if (d.unchanged) {
            T.same = true;
            if (T.data) { T.data.last_scan = d.last_scan || T.data.last_scan; T.data.last_capture = d.last_capture || T.data.last_capture; }
            return;
          }
          keep(d);
          if (poll && T.data && reading()) { T.pending = d; return; }  // keep the page still; offer it instead
          var selId = (rows()[T.sel] || {}).id;
          T.data = d; T.pending = null;
          if (selId != null) { var ni = rows().findIndex(function (r) { return r.id === selId; }); if (ni >= 0) T.sel = ni; }
        });
      return p.then(function () { return T.sess ? null : api("/sessions?hours=24").then(function (d) { if (g === T.gen) T.sess = d; }); }).then(function () {
        done();
        if (!T.alive || g !== T.gen) return;
        T.lastOk = Date.now();
        var stEl = $(".mtt-stamp"); if (stEl.firstChild) stEl.innerHTML = "";  // the stamp only shows a fetch error; a good load clears it
        var recent = ((T.sess && T.sess.sessions) || []).find(function (r) {
          return ["subagent", "cron", "webhook"].indexOf(r.source || "") < 0;
        });
        var gaugeSession = s || T.selectedSession || (T.sess && T.sess.main && T.sess.main.id) || (recent && recent.id);
        loadGauge(gaugeSession, g);
        if (poll && (T.same || T.pending)) { stamp(); return; }
        render();
      }, function (e) { done(); if (g === T.gen) $(".mtt-stamp").innerHTML = '<span class="mt-bad">fetch failed: ' + esc(e.message || e) + "</span>"; });
    }
    // filtered, sorted and paged by the server; "failed" / "recovered" narrow its any-error page to one outcome
    function rows() {
      var rs = (T.data && T.data.rows) || [], ef = c("errs") ? c("errs").value : "";
      if (ef === "failed") return rs.filter(function (r) { return errOf(r).outcome === "failed"; });
      if (ef === "recovered") return rs.filter(function (r) { return errOf(r).recovered; });
      return rs;
    }
    var PAGE = 100;
    function listQuery() {
      return "&limit=" + PAGE + "&sort=" + encodeURIComponent(T.sortKey) + "&dir=" + (T.sortDir > 0 ? "asc" : "desc") +
        (c("misses").checked ? "&misses=1" : "") + (c("slow").checked ? "&slow=1" : "") + (c("errs").value ? "&errors=1" : "");
    }
    function loadMore() {
      if (T.moreLoading || !T.data || !T.data.has_more) return;
      T.moreLoading = true;
      var g = T.gen, base = T.data, off = T.data.rows.length;
      var q = T.lastQ + "&family=" + encodeURIComponent(famParam()) + listQuery() + "&offset=" + off + "&page=1";
      api(q).then(function (d) {
        // the page belongs to the list it was asked for: a reload, filter change or earlier page since then drops it
        if (!T.alive || g !== T.gen || T.data !== base || base.rows.length !== off) return;
        T.data.rows = T.data.rows.concat(d.rows || []);
        T.data.has_more = d.has_more;
        keepAnchor(renderCalls);
      }).then(function () { T.moreLoading = false; }, function () { T.moreLoading = false; });
    }
    function renderGauge() { renderContextGauge($(".mtt-gauge"), T.context); remember(); }
    function loadGauge(sid, generation) {
      if (!sid) { T.context = null; renderGauge(); return; }
      T.selectedSession = sid;
      if (init.onSessionSelected) init.onSessionSelected(sid);
      if (!T.context || T.context.id !== sid) { T.context = { id: sid }; renderGauge(); }  // same session: no blank-then-refill
      api("/inspector/session?id=" + encodeURIComponent(sid) + "&limit=1").then(function (d) {
        if (!T.alive || generation !== T.gen || sid !== T.selectedSession) return;
        T.context = d.context || { id: sid }; renderGauge();
      }, function () {
        if (!T.alive || generation !== T.gen || sid !== T.selectedSession) return;
        T.context = { id: sid }; renderGauge();
      });
    }
    function renderStrip() {
      if (T.tab === "sessions") { setHTML($(".mtt-strip"), ""); return; }
      var fams = (T.data && T.data.summary) || {}, lab = {};  // computed server-side over the whole window
      (T.fams || []).forEach(function (x) { lab[x.family] = x.label; });
      var html = Object.keys(fams).map(function (name) {
        var f = fams[name], hit = f.p ? 100 * f.c / f.p : null;
        return '<div class="mt-card"><div class="mtt-ct"><b>' + esc(lab[name] || name) + '</b> <span class="mt-dim">' + f.n + ' calls</span><span class="mtt-ctr"><i>hit</i> ' + hitHTML(hit) + "</span></div>" +
          '<div class="mtt-ckv"><span><i>lat p50/p95</i> ' + sec(f.lat50) + "/" + sec(f.lat95) + "s</span><span><i>ttfb p50</i> " + sec(f.ttfb50) + "s</span>" +
          '<span><i>misses</i> <b class="' + (f.miss ? "mt-bad" : "") + '">' + f.miss + "</b></span>" +
          '<span class="mtt-errgrp" title="' + esc(ERR_HELP + " Zero means no recorded evidence in this window. 429s count rate-limit responses, a subtype of errors (incl. ones later recovered).") + '"><i>errors</i> ' +
            (f.failed_calls != null
              ? '<i>failed</i> <b class="' + (f.failed_calls ? "mt-bad" : "") + '">' + f.failed_calls + '</b> <i>recovered</i> <b class="' + (f.recovered_calls ? "mt-warn" : "") + '">' + f.recovered_calls +
                "</b> <i>no status</i> " + f.unknown_calls
              : '<i>failed</i> <b class="' + (f.err ? "mt-bad" : "") + '">' + f.err + "</b>") +
            ' · <i>429s</i> <b class="' + (f.n429 ? "mt-bad" : "") + '">' + f.n429 + "</b>" + (f.retry ? " <i>retry</i> " + sec(f.retry) + "s" : "") + "</span>" +
          "<span><i>empty</i> " + f.empty + "</span><span><i>prompt</i> " + kk(f.p) + " <i>cached</i> " + kk(f.c) + "</span>" +
          "<span><i>out</i> " + kk(f.o) + " <i>think</i> " + kk(f.t) + '</span><span><i>cost</i> <b class="mt-warn">' + usd(f.cost) + "</b> <i>equiv</i> " + usd(f.eq) + "</span></div></div>";
      }).join("");
      var keys = (T.data && T.data.keys) || [];  // already filtered server-side by tab and provider
      if (keys.length) {
        var cnt = function (v, cls) { return v == null ? '<td class="mt-dim">—</td>' : '<td class="' + (v ? cls : "mt-dim") + '">' + v + "</td>"; };
        // Proxy failure evidence belongs to a credential (suffix), not to a call-scope group: one key can appear in several
        // family/provider/project rows above, but its failed attempts are counted once, from the key-level records.
        var shownKeys = {};
        keys.forEach(function (x) { shownKeys[x.auth_key] = 1; });
        var fkeys = ((T.data && T.data.fail_keys) || []).filter(function (f) { return f.n && shownKeys[f.key]; });
        html += '<div class="mt-card mtt-wide"><div class="mtt-ct"><b>auth keys</b> <span class="mt-dim">credential of the serving attempt (proxy upstream when logged, else what Hermes sent) · ' +
          "failed / recovered count calls</span></div>" +
          '<div class="mtt-scroll"><table class="mtt-table"><thead><tr><th class="l">family</th><th class="l">key</th><th class="l">scope</th><th>calls</th><th>avg s</th><th>avg hit</th>' +
          '<th title="calls that ended without a successful response">failed</th><th title="calls that succeeded after recorded failures (retry, key rotation or fallback)">recovered</th></tr></thead><tbody>' +
          keys.map(function (x) {
            return '<tr><td class="l">' + esc(lab[x.family] || x.family) + '</td><td class="l">' + esc(mk(x.auth_key)) + ' <span class="mt-chip">' + esc(x.auth_type) + '</span></td><td class="l mt-dim">' + esc([x.upstream_provider || x.provider, x.project].filter(Boolean).join(" · ")) +
              "</td><td>" + x.n + "</td><td>" + sec(x.avg_s) + '</td><td style="color:' + hitColor(x.avg_hit) + '">' + (x.avg_hit == null ? "—" : x.avg_hit.toFixed(0) + "%") +
              "</td>" + cnt(x.failed_calls, "mt-bad") + cnt(x.recovered_calls, "mt-warn") + "</tr>";
          }).join("") + "</tbody></table></div>" +
          // proxy evidence, a different unit: every upstream attempt it logged as failed, retries inside recovered calls included
          (fkeys.length ? '<details class="mtt-attempts"><summary>proxy upstream attempts · ' + fkeys.reduce(function (a, f) { return a + f.n; }, 0) +
            ' failed (retries included; attempts, not calls)</summary><div class="mtt-scroll"><table class="mtt-table"><thead><tr>' +
            '<th class="l" title="matched by the credential\'s last 4 characters; distinct credentials sharing them are combined">key</th>' +
            '<th title="upstream attempts the proxy logged as failed, any status">failed attempts</th><th title="of those: rate-limit (429) responses">of which 429</th><th class="l">last</th></tr></thead><tbody>' +
            fkeys.map(function (f) {
              return '<tr><td class="l">' + esc(mk(f.key)) + "</td>" + cnt(f.n, "mt-bad") + cnt(f.n429 == null ? null : f.n429, "mt-bad") + '<td class="l">' + (f.last ? dt(f.last) : "") + "</td></tr>";
            }).join("") + "</tbody></table></div></details>" : "") + "</div>";
      }
      setHTML($(".mtt-strip"), html);
    }
    function missHTML(dv) {
      if (!dv) return "";
      // the reason itself is already on the call's row (why-miss column / card line): the drawer shows the evidence only
      var change = dv.change, html = '<div class="mtt-miss">';
      if (dv.at != null) html += '<div class="mtt-diff-meta">item #' + dv.at + ' (' + esc(dv.role) + ') · ' + num(dv.prev_len) + ' → ' + num(dv.cur_len) + ' chars' +
        (dv.common_items != null ? ' · prefix ' + dv.common_items + '/' + dv.items : '') + '</div>';
      if (change && change.v === 2) {
        html += '<div class="mtt-diff-path">' + esc(change.path) + ' <span class="mt-dim">line ' + num(change.line) + ', char ' + num(change.offset) + '</span></div>';
        if (change.summary) html += '<div class="mtt-diff-summary">' + esc(change.summary) + '</div>';
        html += '<div class="mtt-diff" aria-label="First changed request value">';
        [["before", "−", "del", "Previous"], ["after", "+", "add", "Current"]].forEach(function (side) {
          var s = change[side[0]] || {};
          html += '<div class="mtt-diff-line is-' + side[2] + '" aria-label="' + side[3] + '"><span class="mtt-diff-sign" aria-hidden="true">' + side[1] + '</span><span class="mtt-diff-code">' +
            (s.omitted_prefix ? '…' : '') + esc(s.prefix || '') +
            (s.change ? '<mark>' + esc(s.change) + (s.omitted_change ? '… [' + num(s.omitted_change) + ' more changed chars]' : '') + '</mark>' : '') +
            esc(s.suffix || '') + (s.omitted_suffix ? '…' : '') + '</span></div>';
        });
        html += '</div>';
      } else if (dv.at != null) html += '<div class="mt-dim">Detailed diff unavailable — compared payloads are no longer captured.</div>';
      return html + '</div>';
    }
    function detHTML(r) {
      var at = r.attempt_detail ? JSON.parse(r.attempt_detail) : [], dv = r.diverge ? JSON.parse(r.diverge) : null, events = r.events || [];
      return '<div class="mtt-det">' + errDetail(r) + missHTML(dv) +
        '<details class="mtt-transport"><summary>Transport details' + (at.length > 1 ? ' · ' + at.length + ' attempts' : '') + (events.length ? ' · ' + events.length + ' events' : '') + '</summary>' +
        '<div><b>' + esc(r.id) + '</b> · status ' + r.status + '</div><div>' + esc(r.url || '') + ' · ' + esc(r.client || '') + '</div>' +
        '<div>session ' + esc(r.session_id || '(unattributed)') + '</div>' +
        (r.file ? '<div>' + esc(r.file) + '</div>' : '') +
        (at.length ? '<div>attempts: ' + at.map(function (a) { return '#' + a.n + ' <span class="' + (a.status === 200 ? 'mt-good' : 'mt-bad') + '">' + (a.status == null ? '?' : a.status) + '</span> ' + esc(a.provider || '') + ' ' + esc(mk(a.key || '')) + (a.s != null ? ' ' + a.s + 's' : ''); }).join(' → ') + '</div>' : '') +
        (events.length ? '<pre class="mt-pre">' + events.map(function (e) { return tm(e.ts) + ' ' + esc(e.kind) + ' ' + esc(e.detail); }).join('\n') + '</pre>' : '') + '</details></div>';
    }
    function flagsOf(r) {
      return { miss: r.prompt_tokens > 20000 && (r.hit_pct || 0) < 50, err: errOf(r).outcome === "failed", empty: errOf(r).outcome === "succeeded" && !r.prompt_tokens, slow: (r.total_s || 0) > 30 };
    }
    var moreObs = null;
    function moreHTML() {
      if (!T.data || !T.data.has_more) return "";
      return '<div class="mtt-more" data-key="more"><button type="button" class="mt-btn" data-a="more">Load older calls · ' + T.data.rows.length + " of " + (T.data.total || "?") + "</button></div>";
    }
    function watchMore() {  // load the next page when its footer scrolls into view
      if (moreObs) moreObs.disconnect();
      var el = root.querySelector(".mtt-more");
      if (!el || !window.IntersectionObserver) return;
      moreObs = new IntersectionObserver(function (es) { if (es.some(function (x) { return x.isIntersecting; })) loadMore(); }, { rootMargin: "400px" });
      moreObs.observe(el);
    }
    function renderCalls() {
      var rs = rows();
      if (T.sel >= rs.length) T.sel = Math.max(0, rs.length - 1);
      var empty = rs.length ? "" : '<div class="mt-empty">no calls in this window' + (T.data && T.data.no_data ? " — nothing captured yet. Enable the plugin and restart the gateway or CLI; every model call shows up here." : "") + "</div>";
      if (mm(MOBILE_Q)) {
        morph($(".mtt-list"), '<div class="mtt-sortbar" data-key="sortbar"><label class="mt-chk">sort <select class="mt-input" data-c="sort">' +
          [["started", "time"], ["errors", "errors"], ["total_s", "total"], ["ttfb_s", "ttfb"], ["hit_pct", "hit"], ["prompt_tokens", "prompt"], ["cost_usd", "cost"]].map(function (o) {
            return '<option value="' + o[0] + '"' + (T.sortKey === o[0] ? " selected" : "") + ">" + o[1] + "</option>";
          }).join("") + '</select></label><button type="button" class="mt-btn" data-a="dir">' + (T.sortDir > 0 ? "▲ asc" : "▼ desc") + '</button><span class="mt-dim">' + rs.length + " calls</span></div>" +
          rs.map(function (r, i) {
            var fl = flagsOf(r), dv = r.diverge ? JSON.parse(r.diverge) : null;
            var lane = r.session_id ? (r.lane || "") + " " + r.session_id.slice(-6) : (r.lane || "");
            return '<div data-id="' + esc(r.id) + '" class="mtt-call' + (fl.miss ? " is-miss" : "") + (fl.err ? " is-err" : "") + (fl.slow ? " is-slow" : "") + (i === T.sel ? " is-sel" : "") + '" tabindex="0">' +
              '<div class="mtt-ch"><b>' + esc(r.model || "?") + "</b>" + (lane ? '<span class="mt-chip">' + esc(lane) + "</span>" : "") + '<span class="mti-ts">' + dt(r.started) + "</span></div>" +
              '<div class="mtt-cm"><span><i>total</i> <b class="' + (fl.slow ? "mt-warn" : "") + '">' + sec(r.total_s) + "s</b></span><span><i>ttfb</i> " + sec(r.ttfb_s) + "s</span><span><i>hit</i> " + hitHTML(r.hit_pct) + "</span></div>" +
              '<div class="mtt-cm"><span><i>prompt</i> ' + kk(r.prompt_tokens) + "</span><span><i>cached</i> " + kk(r.cached_tokens) + "</span><span><i>out</i> " + kk(r.output_tokens) + "</span><span><i>think</i> " + (r.thinking_tokens ? kk(r.thinking_tokens) : "·") + "</span><span><i>cost</i> " + usd(r.cost_usd) + "</span></div>" +
              '<div class="mti-chips">' + (r.auth_key || r.provider ? '<span class="mt-chip">' + esc(mk(r.auth_key || r.provider)) + " · " + esc(r.billing || "") + "</span>" : "") +
              (r.attempts > 1 ? '<span class="mt-chip mt-warnc">' + r.attempts + " attempts</span>" : "") +
              (r.retry_s ? '<span class="mt-chip mt-warnc">retry ' + sec(r.retry_s) + "s</span>" : "") + (r.aff === "rebound" ? '<span class="mt-chip mt-flip">rebound → cold key</span>' : r.aff ? '<span class="mt-chip">' + esc(r.aff) + "</span>" : "") +
              (fl.empty ? '<span class="mt-chip mt-flip">empty</span>' : "") + errChip(r) + "</div>" +
              (dv && dv.why ? '<div class="mtt-why ' + (fl.miss ? "mt-bad" : "mt-dim") + '">' + esc(dv.why) + "</div>" : "") +
              (T.open[r.id] ? detHTML(r) : "") + "</div>";
          }).join("") + (empty ? '<div data-key="empty">' + empty + "</div>" : "") + moreHTML());
        watchMore();
        return;
      }
      var list = $(".mtt-list");
      if (!list.querySelector('.mtt-tall[data-key="calls"]')) {
        list.innerHTML = '<div class="mtt-scroll mtt-tall" data-key="calls"><table class="mtt-table mtt-calls"><thead></thead><tbody></tbody></table>' +
          '<div class="mtt-morewrap"></div></div><div class="mtt-emptywrap"></div>';
        list.__html = null;
      }
      setHTML(list.querySelector(".mtt-calls thead"), "<tr>" + COLS.map(function (x) {
        var tip = COL_TIPS[x[0]];
        return '<th class="' + (x[2] || "") + '" data-sort="' + x[0] + '"' + (tip ? ' title="' + esc(tip) + '"' : "") + ">" + x[1] + (T.sortKey === x[0] ? (T.sortDir > 0 ? " ▲" : " ▼") : "") + "</th>";
      }).join("") + "</tr>");
      var html = "";
      rs.forEach(function (r, i) {
        var fl = flagsOf(r), dv = r.diverge ? JSON.parse(r.diverge) : null;
        var lane = r.session_id ? (r.lane || "") + " " + r.session_id.slice(-6) : (r.lane || "");
        html += '<tr data-id="' + esc(r.id) + '" class="' + (fl.miss ? "is-miss " : "") + (fl.err ? "is-err " : "") + (fl.slow ? "is-slow " : "") + (T.open[r.id] ? "is-open " : "") + (i === T.sel ? "is-sel" : "") + '">' +
          '<td class="l">' + dt(r.started) + '</td><td class="l mt-dim">' + esc(lane) + '</td><td class="l">' + esc(r.model || "?") + (fl.empty ? ' <span class="mt-chip mt-flip">empty</span>' : "") + "</td>" +
          '<td class="l">' + esc(mk(r.auth_key || r.provider || "")) + ' <span class="mt-chip">' + esc(r.billing || "") + "</span></td>" +
          '<td class="' + (r.attempts > 1 ? "mt-warn" : "mt-dim") + '">' + (r.attempts == null ? "" : r.attempts) + "</td>" +
          '<td class="l">' + (errChip(r) || '<span class="mt-dim">·</span>') + "</td>" +
          '<td class="' + (r.retry_s ? "mt-warn" : "mt-dim") + '">' + (r.retry_s ? sec(r.retry_s) : "·") + "</td><td>" + sec(r.ttfb_s) + "</td><td>" + sec(r.gen_s) + '</td><td class="' + (fl.slow ? "mt-warn" : "") + '">' + sec(r.total_s) + "</td>" +
          "<td>" + kk(r.prompt_tokens) + "</td><td>" + kk(r.cached_tokens) + '</td><td class="mtt-hit">' + hitHTML(r.hit_pct) + "</td>" +
          '<td class="mt-dim">' + (r.cache_write_tokens ? kk(r.cache_write_tokens) : "·") + "</td><td>" + kk(r.output_tokens) + "</td><td>" + (r.thinking_tokens ? kk(r.thinking_tokens) : "·") + "</td>" +
          '<td class="' + (r.cost_usd ? "mt-warn" : "mt-dim") + '">' + usd(r.cost_usd) + '</td><td class="mt-dim">' + usd(r.cost_equiv_usd) + "</td>" +
          '<td class="l">' + (r.aff === "rebound" ? '<span class="mt-chip mt-flip">rebound→cold key</span>' : esc(r.aff)) + "</td>" +
          '<td class="l mtt-whycell ' + (fl.miss ? "mt-bad" : "mt-dim") + '" title="' + esc((dv && dv.why) || "") + '">' + esc((dv && dv.why) || "") + "</td></tr>";
        if (T.open[r.id]) html += '<tr class="mtt-detrow" data-key="det:' + esc(r.id) + '"><td colspan="' + COLS.length + '">' + detHTML(r) + "</td></tr>";
      });
      morph(list.querySelector(".mtt-calls tbody"), html);
      setHTML(list.querySelector(".mtt-morewrap"), moreHTML());
      setHTML(list.querySelector(".mtt-emptywrap"), empty);
      watchMore();
    }
    function renderSessions() {
      var s = (T.sess && T.sess.sessions) || [];
      if (mm(MOBILE_Q)) {
        $(".mtt-list").innerHTML = s.map(function (r) {
          return '<button type="button" class="mtt-call mtt-ses" data-session-link="' + esc(r.id) + '"><div class="mtt-ch"><b>' + esc(bareTitle(r.title, r) || r.id) + '</b><span class="mti-ts">' + (r.t ? dt(r.t) : "") + "</span></div>" +
            '<div class="mtt-cm"><span class="mt-chip">' + esc(r.source) + "</span><span>" + esc(r.model || "") + "</span><span><i>calls</i> " + num(r.api_call_count) + "</span></div>" +
            '<div class="mtt-cm"><span><i>hit</i> ' + hitHTML(r.hit_pct) + "</span><span><i>in</i> " + kk(r.input_tokens) + "</span><span><i>cache</i> " + kk(r.cache_read_tokens) + "</span><span><i>out</i> " + kk(r.output_tokens) + "</span><span><i>cost</i> " + usd(r.estimated_cost_usd) + "</span></div>" +
            '<div class="mt-dim mtt-sid">' + esc(r.id) + "</div></button>";
        }).join("") || '<div class="mt-empty">no sessions</div>';
        return;
      }
      $(".mtt-list").innerHTML = '<div class="mtt-scroll mtt-tall"><table class="mtt-table"><thead><tr><th class="l">last active</th><th class="l">session</th><th class="l">source</th><th class="l">model</th><th>calls</th><th>input</th><th>cache read</th><th>cache write</th><th>hit</th><th>output</th><th>reasoning</th><th>est cost</th><th class="l">title</th></tr></thead><tbody>' +
        s.map(function (r) {
          return '<tr><td class="l">' + (r.t ? dt(r.t) : "") + '</td><td class="l"><button type="button" class="mt-link" data-session-link="' + esc(r.id) + '">' + esc(r.id) + '</button></td><td class="l mt-dim">' + esc(r.source) +
            '</td><td class="l">' + esc(r.model) + "</td><td>" + num(r.api_call_count) + "</td><td>" + kk(r.input_tokens) + "</td><td>" + kk(r.cache_read_tokens) + '</td><td class="mt-dim">' + kk(r.cache_write_tokens) +
            '</td><td style="color:' + hitColor(r.hit_pct) + '">' + (r.hit_pct == null ? "—" : r.hit_pct + "%") + "</td><td>" + kk(r.output_tokens) + "</td><td>" + kk(r.reasoning_tokens) + '</td><td class="mt-dim">' + usd(r.estimated_cost_usd) +
            '</td><td class="l mt-dim mtt-whycell" title="' + esc(r.title || "") + '">' + esc(r.title ? bareTitle(r.title, r) : "") + "</td></tr>";
        }).join("") + "</tbody></table></div>";
    }
    function stamp() {
      schedLive();
      // held new calls: a floating button in the overlay layer, outside the page flow, so its arrival moves nothing
      setHTML(newfloat, T.pending ? '<button type="button" class="mt-btn mtt-newpill" data-a="applynew">↻ show new calls</button>' : "");
    }
    function renderAll() { renderTabs(); renderGauge(); renderStrip(); remember(); if (T.tab === "sessions") renderSessions(); else renderCalls(); stamp(); }
    function render() { keepAnchor(renderAll); }
    // Every render rebuilds the list (and its scroll box): keep the reader's place. The anchor is the selected row,
    // else the first row in view; after the rebuild its on-screen top is restored by scrolling whatever scrolls the
    // list (its own box on desktop, the page on phones).
    function listScroller() {
      var tall = root.querySelector(".mtt-tall");
      if (tall && !mm(MOBILE_Q)) return tall;
      for (var p = root.parentElement; p && p !== document.body; p = p.parentElement) {
        var oy = getComputedStyle(p).overflowY;
        if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight + 4) return p;
      }
      return document.scrollingElement || document.documentElement;
    }
    function anchorRow() {
      var sel = rows()[T.sel], list = root.querySelector(".mtt-list");
      var el = sel && list.querySelector('[data-id="' + (window.CSS && CSS.escape ? CSS.escape(sel.id) : sel.id) + '"]');
      if (el) return el;
      var sc = listScroller(), top = sc === document.scrollingElement || sc === document.documentElement ? 0 : sc.getBoundingClientRect().top;
      var all = list.querySelectorAll("[data-id]");
      for (var i = 0; i < all.length; i++) if (all[i].getBoundingClientRect().bottom > top + 1) return all[i];
      return null;
    }
    function keepAnchor(fn) {
      var a = root.isConnected && T.tab !== "sessions" ? anchorRow() : null, id = a && a.dataset.id, was = a && a.getBoundingClientRect().top;
      // reading the head of the list with nothing open: let a new call slide in on top instead of pinning the old first row
      if (a && !Object.keys(T.open).some(function (k) { return T.open[k]; }) && a === root.querySelector(".mtt-list [data-id]")) {
        var sc0 = listScroller(), doc0 = sc0 === document.scrollingElement || sc0 === document.documentElement;
        if (doc0 ? was >= 0 : sc0.scrollTop <= 1) id = null;
      }
      var tall = root.querySelector(".mtt-tall"), st = tall ? tall.scrollTop : 0;
      fn();
      var t2 = root.querySelector(".mtt-tall");
      if (t2 && st) t2.scrollTop = st;  // same list, same offset; then correct for anything that moved above the anchor
      if (!id) return;
      var b = root.querySelector('.mtt-list [data-id="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]');
      if (!b) return;
      var d = b.getBoundingClientRect().top - was;
      if (Math.abs(d) < 1) return;
      var sc = listScroller();
      if (sc === document.scrollingElement || sc === document.documentElement) window.scrollBy(0, d); else sc.scrollTop += d;
    }
    function toggle(i) { var r = rows()[i]; if (!r) return; T.sel = i; T.open[r.id] = !T.open[r.id]; render(); }

    function onClick(e) {
      if (e.target.closest('[data-a="applynew"]')) { if (T.pending) { T.data = T.pending; T.pending = null; render(); } return; }
      var t = e.target.closest(".mt-tab[data-t]");
      if (t && root.contains(t)) { pickTab(t.dataset.t); return; }
      if (e.target.closest('[data-a="fhelp"]')) { hpop.toggle(); return; }
      var th = e.target.closest("th[data-sort]");
      if (th) { var k = th.dataset.sort; if (T.sortKey === k) T.sortDir *= -1; else { T.sortKey = k; T.sortDir = -1; } T.open = {}; load(); return; }
      if (e.target.closest('[data-a="dir"]')) { T.sortDir *= -1; load(); return; }
      if (e.target.closest('[data-a="more"]')) { loadMore(); return; }
      var s = e.target.closest("[data-session-link]");
      if (s && root.contains(s)) { c("sess").value = s.dataset.sessionLink; T.tab = "all"; store("ttab", T.tab); T.reveal = true; load(); return; }
      if (e.target.closest(".mtt-det")) return;
      var row = e.target.closest(".mtt-list [data-id]");
      if (row && root.contains(row)) { var id = row.dataset.id; toggle(rows().findIndex(function (r) { return String(r.id) === id; })); }
    }
    function onKey(e) {
      if (!root.isConnected || typing(e) || e.metaKey || e.ctrlKey || e.altKey) return;
      var n = rows().length, k = e.key;
      if ((k === "Enter" || k === " ") && onControl(e)) return;
      var focusSel = function () { scrollTo(root.querySelector(".mtt-list .is-sel"), "nearest"); };
      if (k === "j") { T.sel = Math.min(n - 1, T.sel + 1); render(); focusSel(); }
      else if (k === "k") { T.sel = Math.max(0, T.sel - 1); render(); focusSel(); }
      else if (k === "Enter") toggle(T.sel);
      else if (k >= "1" && k <= "9") { var tb = tabs()[+k - 1]; if (!tb) return; pickTab(tb[0]); }
      else if (k === "m") c("misses").click();
      else if (k === "s") c("slow").click();
      else if (k === "r") load();
      else return;
      e.preventDefault();
    }
    // tablist keys: ←/→ move focus between tabs (Home/End jump), Enter/Space select — the focused tab is scrolled into view
    var tabsBox = $(".mtt-tabs");
    function onTabKey(e) {
      var t = e.target.closest && e.target.closest(".mt-tab[data-t]");
      if (!t) return;
      var all = Array.prototype.slice.call(tabsBox.querySelectorAll(".mt-tab[data-t]")), i = all.indexOf(t), j;
      if (e.key === "ArrowRight") j = Math.min(all.length - 1, i + 1);
      else if (e.key === "ArrowLeft") j = Math.max(0, i - 1);
      else if (e.key === "Home") j = 0;
      else if (e.key === "End") j = all.length - 1;
      else return;
      e.preventDefault(); e.stopPropagation();
      try { all[j].focus({ preventScroll: true }); } catch (x) { all[j].focus(); }
      revealTab(all[j]); fades();
    }
    // a vertical wheel over an overflowing strip scrolls it sideways (trackpads' horizontal swipes pass through)
    function onTabWheel(e) {
      var s = e.target.closest && e.target.closest(".mtt-fstrip");
      if (!s || s.scrollWidth <= s.clientWidth + 1 || Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
      e.preventDefault();
      s.scrollLeft += e.deltaY;
    }
    function onTabScroll(e) { if (e.target && e.target.classList && e.target.classList.contains("mtt-fstrip")) fades(); }
    function onChange(e) {
      var d = e.target.dataset && e.target.dataset.c;
      if (d === "hours" || d === "sess") { T.reveal = true; load(); }

      else if (d === "sort") { T.sortKey = e.target.value; load(); }
      else if (d === "misses" || d === "slow" || d === "errs") { T.open = {}; T.sel = 0; load(); }
      else if (d === "auto") schedLive();
    }
    root.addEventListener("click", onClick);
    layer.addEventListener("click", onClick);  // the floating "show new calls" button lives in the overlay layer
    root.addEventListener("change", onChange);

    tabsBox.addEventListener("keydown", onTabKey);
    tabsBox.addEventListener("wheel", onTabWheel, { passive: false });
    tabsBox.addEventListener("scroll", onTabScroll, true);
    document.addEventListener("scroll", schedLive, true);
    document.addEventListener("keydown", onKey);
    var tro = window.ResizeObserver ? new ResizeObserver(fades) : null;
    if (tro) tro.observe(tabsBox);
    var mq = window.matchMedia(MOBILE_Q), onMQ = function () { hpop.close(); if (T.data || T.sess) render(); };
    if (mq.addEventListener) mq.addEventListener("change", onMQ);
    var timer = setInterval(function () { if (c("auto").checked && !document.hidden) load(true); else stamp(); }, 5000);
    T.reveal = KEPT.fam ? "keep" : true;
    load();
    return function () {
      T.alive = false;
      clearInterval(timer);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("scroll", schedLive, true);
      root.removeEventListener("click", onClick);
      layer.removeEventListener("click", onClick);
      root.removeEventListener("change", onChange);

      tabsBox.removeEventListener("keydown", onTabKey);
      tabsBox.removeEventListener("wheel", onTabWheel);
      tabsBox.removeEventListener("scroll", onTabScroll, true);
      if (tro) tro.disconnect();
      if (liveRaf) cancelAnimationFrame(liveRaf);
      hpop.close(); hpop.destroy();
      if (mq.removeEventListener) mq.removeEventListener("change", onMQ);
      layer.remove();
    };
  }

  // ───────────────────────── tab shell ─────────────────────────
  var VIEWS = [["inspector", "Session & Wire", "Inspector"], ["telemetry", "Calls & Cache", "Calls"]];  // short label ≠ the Wire mode tab

  function readQuery() {
    if (SDK.readQuery) return SDK.readQuery();
    try {
      var q = new URLSearchParams(window.location.search);
      return { view: q.get("view"), session: q.get("session"), row: q.get("row"), tab: q.get("tab"), mode: q.get("mode"), call: q.get("call") };
    } catch (e) { return {}; }
  }

  function Health(props) {
    var health = props.health;
    if (!health) return h("span", { className: "mt-health mt-dim" }, "capture …");
    if (health.error) return h("span", { className: "mt-health mt-bad" }, "API: " + health.error.slice(0, 120));
    var last = health.last_capture && health.last_capture.ts, age = last ? Math.round(Date.now() / 1000 - last) : null;
    var label = health.no_data ? "no calls captured yet" : "capture " + (age == null ? "—" : ago(last)) + " ago · " + num(health.wire_calls) + " requests";
    return h("span", { className: "mt-health mt-dim", title: health.db },
      h("span", { className: "mt-dot" + (health.no_data ? " is-idle" : "") }), h("span", { className: "mt-healtht" }, label));
  }

  function Hints(props) {
    var health = props.health;
    if (!health || health.error || !health.no_data) return null;
    return h("div", { className: "mt-hints", role: "note" },
      h("div", { className: "mt-hintrow" }, h("span", { className: "mt-hinti", "aria-hidden": "true" }, "ⓘ"),
        h("span", null, "No model calls captured yet. Enable the plugin (",
          h("code", null, "hermes plugins enable wiretap"), "), restart the gateway or CLI, and send a message — every call appears here.")));
  }

  function Page() {
    var init = useRef(readQuery()).current;
    var vs = useState(init.view || store("view") || "inspector"), view = vs[0], setView = vs[1];
    var ns = useState(0), nonce = ns[0], setNonce = ns[1];
    var hs = useState(null), health = hs[0], setHealth = hs[1];
    var ref = useRef(null);
    var selectedSession = useRef(init.session || null);
    useEffect(function () {
      var alive = true;
      function tick() {
        api("/health").then(function (d) { if (alive) setHealth(d); }, function (e) { if (alive) setHealth({ error: String((e && e.message) || e) }); });
      }
      tick();
      var id = setInterval(tick, 15000);
      return function () { alive = false; clearInterval(id); };
    }, []);
    useEffect(function () {
      var el = ref.current;
      if (!el) return undefined;
      var cleanup = null;
      var mountOptions = Object.assign({}, nonce ? {} : init, {
        session: selectedSession.current || init.session,
        onSessionSelected: function (sid) { selectedSession.current = sid; }
      });
      try { cleanup = (view === "telemetry" ? mountTelemetry : mountInspector)(el, mountOptions); }
      catch (e) { el.innerHTML = '<div class="mt-empty mt-bad">' + esc((e && e.message) || e) + "</div>"; }
      return function () { try { if (cleanup) cleanup(); } catch (e) { /* ignore */ } el.innerHTML = ""; };
    }, [view, nonce]);
    return h("div", { className: "mt-root", "data-host": SDK.host || "dashboard" },
      h("div", { className: "mt-bar" },
        h("span", { className: "mt-brand", title: "Wiretap · Wire & Cache Inspector (plugin: wiretap)" },
          h("b", null, "Wiretap"), h("span", { className: "mt-long mt-dim" }, " · Wire & Cache Inspector")),
        h("div", { className: "mt-views" }, VIEWS.map(function (v) {
          return h("button", {
            key: v[0], type: "button", className: "mt-tab mt-viewbtn" + (v[0] === view ? " is-on" : ""),
            onClick: function () { setView(v[0]); store("view", v[0]); },
          }, h("span", { className: "mt-long" }, v[1]), h("span", { className: "mt-short" }, v[2]));
        })),
        h(Health, { health: health }),
        h("button", { type: "button", className: "mt-btn mt-reload", title: "Reload view", "aria-label": "Reload view", onClick: function () { setNonce(nonce + 1); } }, "↻")
      ),
      h(Hints, { health: health }),
      h("div", { ref: ref, className: "mt-mount" })
    );
  }

  return { Page: Page, mountInspector: mountInspector, mountTelemetry: mountTelemetry, partKey: partKey, jsonPanel: jsonPanel, copyFrom: copyFrom };
  }
  // END SHARED WIRETAP RENDERER

  var SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK || !window.__HERMES_PLUGINS__) return;
  var ui = createWiretapUI(SDK);
  window.__HERMES_PLUGINS__.register("wiretap", ui.Page);
  if (window.__WIRETAP_TEST__) window.__WIRETAP_TEST__.expose(ui);
})();
