// Execute the shipped native ESM entry with real React, jsdom and backend responses.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { createRequire } from 'node:module';
const [bundle, dependencyRoot, fixturesFile] = process.argv.slice(2);
const require = createRequire(path.join(dependencyRoot, 'package.json'));
const { JSDOM } = require('jsdom');
const React = require('react');
const { createRoot } = require('react-dom/client');
const fixtures = JSON.parse(fs.readFileSync(fixturesFile, 'utf8'));
const dom = new JSDOM('<!doctype html><body><div id="root"></div></body>', {
  url: 'https://desktop.test/', runScripts: 'outside-only', pretendToBeVisual: true,
});
const w = dom.window;
globalThis.window = w; globalThis.document = w.document;
w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
w.HTMLElement.prototype.scrollIntoView = () => {};
const calls = [], navigations = [], stored = new Map();
let health = fixtures['/health'];
const atom = value => ({get: () => value});
const sdk = {host: {state: {profile: atom('contract'), connectionId: atom('local')},
  navigate: route => navigations.push(route)}, useValue: store => store.get(),
  PALETTE_AREA: 'palette', ROUTES_AREA: 'routes', SIDEBAR_NAV_AREA: 'sidebar.nav'};
const context = dom.getInternalVMContext();
const modules = {
  react: new vm.SyntheticModule(Object.keys(React), function () {
    for (const key of Object.keys(React)) this.setExport(key, React[key]);
  }, {context}),
  '@hermes/plugin-sdk': new vm.SyntheticModule(Object.keys(sdk), function () {
    for (const key of Object.keys(sdk)) this.setExport(key, sdk[key]);
  }, {context}),
};
const mod = new vm.SourceTextModule(fs.readFileSync(bundle, 'utf8'), {context});
await mod.link(name => modules[name]);
await mod.evaluate();
function register() {
  const contributions = [], disposers = [];
  mod.namespace.default.register({
    storage: {get: (key, fallback) => stored.has(key) ? stored.get(key) : fallback,
      set: (key, value) => stored.set(key, value)},
    onDispose: fn => disposers.push(fn),
    registerMany: cs => contributions.push(...cs),
    rest: async suffix => {
      calls.push(suffix);
      const route = suffix.split('?')[0];
      if (!(route in fixtures)) throw Error('Missing fixture for ' + suffix);
      return structuredClone(route === '/health' ? health : fixtures[route]);
    },
  });
  return {route: contributions.find(c => c.area === 'routes'), contributions,
    dispose: () => disposers.forEach(fn => fn())};
}
const first = register();
assert.equal(w.document.head.querySelectorAll('style[data-wiretap]').length, 1);
const previousStyle = w.document.head.querySelector('style[data-wiretap]');
const active = register();
assert.equal(w.document.head.querySelectorAll('style[data-wiretap]').length, 1, 're-register must not duplicate CSS');
assert.equal(previousStyle.isConnected, false, 'stale style must be replaced');
first.dispose();
assert.equal(w.document.head.querySelectorAll('style[data-wiretap]').length, 1, 'late old disposal cannot remove current CSS');
active.contributions.find(c => c.area === 'palette' && c.data.id === 'wiretap.open').data.run();
assert.deepEqual(navigations, ['/wiretap']);
let root;
const waitFor = async predicate => {
  for (let i = 0; i < 200; i++) {
    if (predicate()) return;
    await new Promise(r => setTimeout(r, 5));
  }
  throw Error('Render timed out: ' + w.document.body.textContent);
};
async function mount(hash = '', search = '') {
  if (root) root.unmount();
  dom.reconfigure({url: 'https://desktop.test/' + search + hash});
  root = createRoot(w.document.getElementById('root'));
  root.render(React.createElement(active.route.render));
  await waitFor(() => w.document.querySelector('.mt-healtht'));
}
const isCalls = () => !!w.document.querySelector('.mtt');
const isInspector = () => !!w.document.querySelector('.mti');
const hint = () => w.document.querySelector('.mt-hints')?.textContent || '';
try {
  await mount();
  await waitFor(() => w.document.querySelector('.mti-ses'));
  const page = w.document.querySelector('#root > .mt-root');
  assert.equal(page.dataset.host, 'desktop');
  // Check applied style on the mounted page, not text in a source stylesheet.
  const style = w.getComputedStyle(page);
  assert.equal(style.display, 'flex');
  assert.equal(style.flex, '1 1 auto');
  assert.equal(style.height, '100%');
  assert.equal(parseFloat(style.minHeight), 0);
  assert.equal(style.overflow, 'auto');
  assert.equal(style.getPropertyValue('--mt-chrome').trim(), '8rem');
  // jsdom exposes the cascaded custom-property references (it does not resolve
  // CSS var()/color-mix()). These prove the Desktop skin wins the live cascade.
  for (const [token, host] of Object.entries({
    '--background-base': '--ui-bg-chrome', '--midground-base': '--ui-base',
    '--color-background': '--ui-bg-chrome', '--color-foreground': '--ui-text-primary',
    '--color-muted-foreground': '--ui-text-tertiary', '--color-border': '--ui-stroke-secondary',
    '--color-primary': '--ui-accent', '--color-ring': '--ui-accent', '--color-card': '--ui-bg-card',
    '--color-success': '--ui-green', '--color-warning': '--ui-yellow', '--color-destructive': '--ui-red',
  })) assert.equal(style.getPropertyValue(token).trim(), `var(${host})`, token);
  const portal = w.document.querySelector('.mt-layer');
  assert.equal(w.getComputedStyle(portal).display, 'contents', 'portal must not acquire page scrolling');
  assert.equal(w.getComputedStyle(portal).getPropertyValue('--color-foreground').trim(), 'var(--ui-text-primary)');
  w.document.querySelector('.mti-ses').click();
  await waitFor(() => calls.some(url => url.startsWith('/inspector/compiled')) &&
    w.document.body.textContent.includes('synthetic contract request'));
  w.document.querySelectorAll('.mt-viewbtn')[1].click();
  await waitFor(() => w.document.body.textContent.includes('contract-model'));
  assert.equal(stored.get('view'), 'telemetry', 'view changes must use ctx.storage');
  assert.equal(w.document.querySelector('iframe'), null);

  // Stock users are not prompted to install an optional proxy. Only an
  // explicitly configured missing proxy should produce the setup banner.
  for (const [proxy, expected] of [[undefined, false], [{exists: false}, false],
    [{configured: false, exists: false}, false], [{configured: true, exists: true}, false],
    [{configured: true, exists: false}, true]]) {
    health = {...fixtures['/health'], no_data: false, proxy};
    await mount('#/wiretap?view=telemetry');
    assert.equal(hint().includes('CLIProxyAPI'), expected, JSON.stringify(proxy));
  }
  w.document.querySelector('.mt-hintx').click();
  await waitFor(() => !hint().includes('CLIProxyAPI'));
  assert.equal(stored.get('hint-dismissed').proxy, 1, 'dismissal persists through ctx.storage');
  await mount('#/wiretap?view=telemetry');
  assert.equal(hint().includes('CLIProxyAPI'), false, 'dismissed hint must stay dismissed');
  health = {...fixtures['/health'], no_data: true, proxy: {configured: false, exists: false}};
  await mount();
  assert.ok(hint().includes('No model calls captured yet'), 'stock no-data guidance remains visible');
  assert.equal(hint().includes('CLIProxyAPI'), false);
  health = fixtures['/health'];

  // Hash query belongs only to this route. Outer app parameters, unrelated
  // routes, missing queries and unrecognized views cannot hijack the page.
  for (const [hash, search, saved, expected] of [
    ['#/wiretap?view=telemetry', '', 'inspector', 'telemetry'],
    ['#/wiretap?view=inspector', '?view=telemetry', 'telemetry', 'inspector'],
    ['', '?view=telemetry', 'inspector', 'inspector'],
    ['#/wiretap', '', 'telemetry', 'telemetry'],
    ['#/other?view=telemetry', '', 'inspector', 'inspector'],
    ['#/wiretap?view=unrecognized', '', 'telemetry', 'telemetry'],
    ['#/wiretap?view=%74elemetry', '', 'inspector', 'telemetry'],
  ]) {
    stored.set('view', saved);
    await mount(hash, search);
    assert.equal(expected === 'telemetry' ? isCalls() : isInspector(), true, hash || 'empty hash');
  }
  calls.length = 0;
  stored.set('view', 'telemetry');
  await mount('#/wiretap?view=inspector&session=contract-session&mode=transcript&tab=wire');
  await waitFor(() => w.document.body.textContent.includes('synthetic contract request'));
  assert.ok(calls.some(url => url.startsWith('/inspector/session?') && url.includes('id=contract-session')),
    'hash session and transcript mode must reach the inspector');
  assert.ok(!calls.some(url => url.startsWith('/inspector/compiled?')), 'transcript link must not fetch compiled mode');
  assert.equal(w.document.querySelector('.mt-viewbtn.is-on .mt-long').textContent, 'Session & Wire');
  console.log(JSON.stringify({inspector: true, callsView: true, native: true, palette: true,
    styleLifecycle: true, renderedTheme: true, proxyBanner: true, hashLinks: true, storage: true}));
} finally {
  if (root) root.unmount();
  active.dispose();
  assert.equal(w.document.head.querySelectorAll('style[data-wiretap]').length, 0, 'plugin disposal must remove CSS');
  assert.equal(w.document.querySelector('.mt-layer'), null, 'inspector overlays must unmount');
  dom.window.close();
}
