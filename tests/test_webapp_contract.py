"""Executable classic-dashboard and native Desktop host-contract checks.

Classic dashboard: real stock discovery, HTTP routes, auth gate, static assets,
and registry execution. Desktop: execute its real filesystem reconciliation,
SDK injection, context scoping, and ESM runtime loader. No server sockets, browser,
provider calls, or existing user profile are used. Set PYTHONPATH to Hermes.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent.parent


def _classic_probe(home: Path, headless=False):
    """Run in a fresh process, before any Hermes globals resolve a profile."""
    home.mkdir(parents=True, exist_ok=True)
    (home / 'plugins').mkdir()
    (home / 'plugins' / 'wiretap').symlink_to(HERE, target_is_directory=True)
    settings = {'plugins': {'enabled': ['wiretap'], 'isolation': 'in_process',
                           'entries': {'wiretap': {'settings': {'proxy_poller': False,
                                                              'proxy_log_dir': str(home / 'absent-logs')}}}}}
    (home / 'config.yaml').write_text(json.dumps(settings), encoding='utf-8')
    os.environ.update(HERMES_HOME=str(home), HERMES_ENABLE_PROJECT_PLUGINS='0',
                      CLIPROXY_LOG_DIR=str(home / 'absent-logs'),
                      HERMES_SERVE_HEADLESS='1' if headless else '0',
                      HERMES_DASHBOARD_SESSION_TOKEN='wiretap-contract-nonsecret-token')
    os.environ.pop('TELEMETRY_DB', None)
    os.environ.pop('WIRETAP_STATE_DB', None)

    import test_schemas as fixtures
    db = sqlite3.connect(home / 'state.db')
    db.executescript(fixtures.STOCK_SCHEMA)
    fixtures._insert(db, 'sessions', {'id': 'contract-session', 'source': 'cli', 'started_at': time.time()})
    fixtures._insert(db, 'messages', {'session_id': 'contract-session', 'role': 'user',
                                     'content': 'synthetic contract request', 'timestamp': time.time()})
    db.commit()
    db.close()

    from fastapi.testclient import TestClient
    from hermes_cli import web_server as server
    from hermes_cli import web_server_dashboard as host
    discovered = host._discover_dashboard_plugins([(home / 'plugins', 'user')])
    assert len(discovered) == 1, discovered
    plugin = discovered[0]
    # No TestClient context: do not run the server lifespan or start services.
    client = TestClient(server.app)
    headers = {server._SESSION_HEADER_NAME: server._SESSION_TOKEN}
    inventory = client.get('/api/dashboard/plugins')
    assert inventory.status_code == 200, inventory.text
    manifest = next(p for p in inventory.json() if p['name'] == 'wiretap')
    assert manifest['tab']['path'] == '/wiretap', manifest
    assert manifest['has_api'] is True, manifest
    assert not any(k.startswith('_') for k in manifest), manifest
    assets = {}
    for key in ('entry', 'css'):
        response = client.get('/dashboard-plugins/wiretap/' + manifest[key])
        assert response.status_code == 200, response.text
        assert response.content == (HERE / 'dashboard' / manifest[key]).read_bytes()
        assets[key] = response.headers['content-type']
    denied_source = client.get('/dashboard-plugins/wiretap/plugin_api.py')
    assert denied_source.status_code == 404, denied_source.text
    unauthenticated = client.get('/api/plugins/wiretap/health')
    assert unauthenticated.status_code == 401, unauthenticated.text
    health = client.get('/api/plugins/wiretap/health', headers=headers)
    assert health.status_code == 200, health.text
    assert health.json()['no_data'] is True, health.text
    tdb = home / 'plugin-data' / 'wiretap' / 'telemetry.db'
    assert not tdb.exists(), 'empty dashboard must not create a telemetry database'

    ins = fixtures._load_inspector()
    con = ins.store.connect(tdb)
    ins.store.init(con)
    now = time.time()
    fixtures._add_call(ins, con, 'contract-call', 'contract-session', now,
                       [{'role': 'user', 'content': 'synthetic contract request'}], text='synthetic answer')
    ins.store.upsert(con, {'id': 'contract-call', 'session_id': 'contract-session', 'source': 'hermes',
                          'started': now, 'ended': now + 1, 'family': 'openai', 'provider': 'test-provider',
                          'model': 'contract-model', 'status': 200, 'prompt_tokens': 20, 'output_tokens': 3}, 'calls')
    con.commit()
    con.close()
    responses = {}
    for name, url in {
        'calls': '/calls',
        'transcript': '/inspector/session?id=contract-session',
        'compiled': '/inspector/compiled?id=contract-session',
        'request_item': '/inspector/wire/part?id=contract-call&part=item&i=0',
        'session_list': '/inspector/sessions',
        'session_summary': '/sessions',
    }.items():
        response = client.get('/api/plugins/wiretap' + url, headers=headers)
        assert response.status_code == 200, (url, response.text)
        responses[name] = response.json()
    assert responses['calls']['rows'][0]['model'] == 'contract-model', responses['calls']
    assert responses['transcript']['rows'][0]['content'] == 'synthetic contract request'
    assert responses['compiled']['call_id'] == 'contract-call', responses['compiled']
    assert 'synthetic contract request' in json.dumps(responses['request_item'])
    native_fixtures = {
        '/health': client.get('/api/plugins/wiretap/health', headers=headers).json(),
        '/calls': responses['calls'], '/sessions': responses['session_summary'],
        '/inspector/sessions': responses['session_list'], '/inspector/session': responses['transcript'],
        '/inspector/compiled': responses['compiled'], '/inspector/wire/part': responses['request_item'],
    }
    print(json.dumps({'discovered': plugin['name'], 'manifest': manifest, 'assets': assets,
                      'private_source_status': denied_source.status_code,
                      'unauthenticated_api_status': unauthenticated.status_code,
                      'empty_store_stays_absent': True, 'populated_endpoints': list(responses),
                      'source': server.__file__, 'headless': headless, 'native_fixtures': native_fixtures}))


# Execute the stock SDK registry rather than reproducing its registration API.
# Renderer-only imports are replaced by tiny doubles; the registry and shipped
# Wiretap bundle execute unchanged. This is not a full browser/React render.
_REGISTRY_PROBE = r'''
import fs from 'node:fs';
import vm from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
const [registryFile, bundleFile] = process.argv.slice(2);
const calls = [], effects = [], cleanups = [];
const noop = () => {};
const react = {createElement: (type, props, ...children) => ({type, props, children}),
  useState: value => [value, noop], useRef: value => ({current: value}),
  useEffect: effect => effects.push(effect)};
const context = {console, Map, Set, queueMicrotask, URLSearchParams,
  setInterval: () => 1, clearInterval: noop, document: {currentScript: null}};
context.window = {location: {search: '', hash: ''}, localStorage: {getItem: () => null, setItem: noop}};
let source = fs.readFileSync(registryFile, 'utf8');
source = source.replace(/^import\s+([\s\S]*?)\s+from\s+["'][^"']+["'];/gm, (_, clause) => {
  for (const name of clause.replace(/[{},]/g, ' ').trim().split(/\s+/)) {
    if (name) context[name] = noop;
  }
  return '';
});
Object.assign(context, {React: react, ...react,
  fetchJSON: url => {calls.push(url); return Promise.resolve({no_data: true});}});
source = stripTypeScriptTypes(source, {mode: 'transform'}).replace(/^export\s+/gm, '');
vm.createContext(context);
vm.runInContext(source, context, {filename: registryFile});
context.exposePluginSDK();
vm.runInContext(fs.readFileSync(bundleFile, 'utf8'), context, {filename: bundleFile});
const Page = context.getPluginComponent('wiretap');
if (typeof Page !== 'function') throw Error('Wiretap did not register with stock registry');
const tree = Page();
for (const effect of effects) { const cleanup = effect(); if (cleanup) cleanups.push(cleanup); }
await Promise.resolve();
cleanups.forEach(fn => fn());
if (!calls.includes('/api/plugins/wiretap/health')) throw Error('health request did not use stock SDK fetchJSON');
console.log(JSON.stringify({registered: context.getRegisteredCount(), sdkVersion: context.window.__HERMES_PLUGIN_SDK__.sdkVersion,
  root: tree.type, calls}));
'''

_DESKTOP_PROBE = r'''
import fs from 'node:fs';
import path from 'node:path';
import * as nodeModule from 'node:module';
import { pathToFileURL } from 'node:url';
const [moduleFile, home, packageDir] = process.argv.slice(2);
// Hermes's Electron sources are bundler-resolved: newer checkouts import sibling TypeScript without an extension.
if (typeof nodeModule.registerHooks === 'function') {
  nodeModule.registerHooks({resolve(specifier, context, nextResolve) {
    try { return nextResolve(specifier, context); } catch (error) {
      if (error?.code !== 'ERR_MODULE_NOT_FOUND' || !/^\.{1,2}\//.test(specifier) || path.extname(specifier)) throw error;
      return nextResolve(specifier + '.ts', context);
    }
  }});
}
const host = await import(pathToFileURL(moduleFile));
const root = path.join(home, 'desktop-plugins');
await fs.promises.mkdir(path.join(home, 'plugins'), {recursive: true});
await fs.promises.symlink(packageDir, path.join(home, 'plugins', 'wiretap'), 'dir');
// Positive control proves reconciliation actually finds a native desktop half.
const positive = path.join(home, 'plugins', 'contract-positive', 'desktop');
await fs.promises.mkdir(positive, {recursive: true});
await fs.promises.writeFile(path.join(positive, 'plugin.js'), 'export default {id: "contract-positive", register() {}};');
const copied = await host.reconcileUnifiedDesktopHalves(home, root);
const materialized = (await fs.promises.readdir(root)).sort();
if (!materialized.includes('contract-positive')) throw Error('native Desktop positive control was not discovered');
if (!materialized.includes('wiretap')) throw Error('Wiretap native desktop half was not materialized');
if (fs.readFileSync(path.join(root, 'wiretap', 'plugin.js'), 'utf8') !== fs.readFileSync(path.join(packageDir, 'desktop', 'plugin.js'), 'utf8')) {
  throw Error('Desktop materialized a different Wiretap entry');
}
console.log(JSON.stringify({copied: copied.map(p => path.basename(p)), materialized,
  wiretapNativeEntry: true, contractModule: moduleFile}));
'''

_DESKTOP_LOADER_PROBE = r'''
import fs from 'node:fs';
import vm from 'node:vm';
import { stripTypeScriptTypes } from 'node:module';
const [sdkFile, loaderFile, contextFile, apiFile, bundleFile] = process.argv.slice(2);
const records = {}, blobs = new Map(), contributions = [], calls = [], effects = [], cleanups = [];
const styles = new Set(), navigations = [];
const atom = value => ({get: () => value, set: next => {value = next;}, listen: () => () => {}});
const noop = () => {};
const react = {Fragment: 'fragment', createElement: (type, props, ...children) => ({type, props, children}),
  useState: value => [value, noop], useRef: value => ({current: value}), useEffect: effect => effects.push(effect)};
const profile = atom('profile-a'), connectionId = atom('connection-a');
const context = {console: {info: noop, warn: noop, error: noop}, Blob, Map, Set, Promise,
  setTimeout, clearTimeout, setInterval: () => 1, clearInterval: noop,
  sdk: {host: {state: {profile, connectionId}, navigate: path => navigations.push(path)},
    useValue: store => store.get(), PALETTE_AREA: 'palette', ROUTES_AREA: 'routes', SIDEBAR_NAV_AREA: 'sidebar.nav'},
  URLSearchParams, location: {hash: ''},
  document: {head: {querySelectorAll: () => [...styles], appendChild: el => styles.add(el)},
    createElement: () => ({setAttribute: noop, remove() {styles.delete(this);}})},
  React: react, jsxRuntime: {}, jsxDevRuntime: {}, atom,
  URL: {createObjectURL: blob => {const key = 'blob:contract/' + blobs.size; blobs.set(key, blob); return key;},
        revokeObjectURL: noop},
  $pluginRecords: atom(records), publishPlugin: record => {records[record.id] = record;},
  pluginActive: () => true, declaredCapabilities: () => [],
  trackGatewayEventDisposers: (_, run) => run(),
  registry: {register: c => {contributions.push(c); return noop;}, registerMany: cs => {contributions.push(...cs); return noop;}},
  hermesDesktop: {api: noop},
  hermesApi: opts => {calls.push(opts); return Promise.resolve({no_data: true});},
  profileScoped: () => ({profile: profile.get(), connectionId: connectionId.get()}),
  readKey: () => null, writeKey: noop, $petActive: atom(false), listPluginAppActions: () => [],
  createPluginPreview: () => ({}), createPluginFiles: () => ({}), createPluginI18n: () => ({}),
  dropPlugin: noop, notifyError: noop, forgetPluginPreviewAccess: noop, isReadFileErrorResult: () => false};
context.window = context;
vm.createContext(context);
const moduleCache = new Map();
const link = async specifier => {
  if (moduleCache.has(specifier)) return moduleCache.get(specifier);
  const blob = blobs.get(specifier);
  if (!blob) throw Error('unknown contract blob: ' + specifier);
  const mod = new vm.SourceTextModule(await blob.text(), {context});
  moduleCache.set(specifier, mod);
  await mod.link(link);
  return mod;
};
const dynamicImport = async specifier => {
  const mod = await link(specifier);
  await mod.evaluate();
  return mod;
};
for (const filename of [sdkFile, apiFile, contextFile, loaderFile]) {
  let source = fs.readFileSync(filename, 'utf8').replace(/^import\s+[\s\S]*?\s+from\s+['"][^'"]+['"]\s*;?\n/gm, '');
  source = stripTypeScriptTypes(source, {mode: 'transform'}).replace(/^export\s+/gm, '');
  vm.runInContext(source, context, {filename, importModuleDynamically: dynamicImport});
}
const positive = await context.loadRuntimePlugin('export default {id: "positive", register() {}}', 'positive');
if (positive !== 'positive' || records.positive.status !== 'loaded') throw Error('Desktop loader positive control failed');
const actual = await context.loadRuntimePlugin(fs.readFileSync(bundleFile, 'utf8'), 'wiretap-native');
if (actual !== 'wiretap' || records.wiretap?.status !== 'loaded') {
  throw Error('Desktop loader failed: ' + JSON.stringify(records));
}
const route = contributions.find(c => c.id === 'wiretap:page');
const nav = contributions.find(c => c.id === 'wiretap:nav');
const command = contributions.find(c => c.area === 'palette' && c.data.id === 'wiretap.open');
if (!route || route.area !== 'routes' || route.data.path !== '/wiretap' || !nav || nav.data.path !== '/wiretap') {
  throw Error('Native route/sidebar contributions missing: ' + JSON.stringify(contributions));
}
if (!command || command.data.label !== 'Open Wiretap') throw Error('Native palette command missing');
command.data.run();
if (navigations.join() !== '/wiretap') throw Error('Palette did not navigate through the host');
if (styles.size !== 1) throw Error('Native stylesheet not installed once');
const shell = route.render();
const page = shell.type();
const rendered = page.type();
for (const effect of effects) {const cleanup = effect(); if (cleanup) cleanups.push(cleanup);}
await Promise.resolve();
cleanups.forEach(fn => fn());
if (!calls.some(c => c.path === '/api/plugins/wiretap/health' && c.profile === 'profile-a' && c.connectionId === 'connection-a')) {
  throw Error('Native page did not use profile/namespace-scoped Desktop API');
}
profile.set('profile-b');
const switched = shell.type();
if (switched.props.key === page.props.key) throw Error('Profile change did not remount inspector');
connectionId.set('connection-b');
if (shell.type().props.key === switched.props.key) throw Error('Connection change did not remount inspector');
context.unloadRuntimePlugin('wiretap');
if (styles.size) throw Error('Host unload did not remove native stylesheet');
await context.loadRuntimePlugin(fs.readFileSync(bundleFile, 'utf8'), 'wiretap-reload');
if (styles.size !== 1) throw Error('Host reload duplicated the stylesheet');
context.unloadRuntimePlugin('wiretap');
if (styles.size) throw Error('Host reload/unload leaked stylesheet');
console.log(JSON.stringify({positive, wiretap: actual, route: route.data.path, nav: nav.data.label,
  root: rendered.type, calls, profileRemount: true, connectionRemount: true, palette: navigations,
  styleLifecycle: true}));
'''


_NATIVE_RENDER_PROBE = (HERE / 'desktop/test-native.mjs').read_text(encoding='utf-8')


class WebappContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.find_spec('hermes_cli')
        if spec is None or not spec.submodule_search_locations:
            raise unittest.SkipTest('Hermes source required on PYTHONPATH')
        cls.stock = Path(next(iter(spec.submodule_search_locations))).parent
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_json(self, argv, **kw):
        result = subprocess.run(argv, text=True, capture_output=True, timeout=90, **kw)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_classic_discovery_static_auth_and_populated_api(self):
        receipt = self.run_json([sys.executable, str(Path(__file__).resolve()), '--classic-probe',
                                 str(self.root / 'classic')], cwd=HERE)
        self.assertEqual(receipt['discovered'], 'wiretap')
        self.assertIn('javascript', receipt['assets']['entry'])
        self.assertIn('text/css', receipt['assets']['css'])
        self.assertEqual(receipt['unauthenticated_api_status'], 401)
        self.assertEqual(set(receipt['populated_endpoints']),
                         {'calls', 'transcript', 'compiled', 'request_item', 'session_list', 'session_summary'})

    def test_stock_classic_sdk_registers_tab_and_routes_health_through_sdk(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node required for JavaScript contract checks')
        probe = self.root / 'registry-probe.mjs'
        probe.write_text(_REGISTRY_PROBE, encoding='utf-8')
        receipt = self.run_json([node, str(probe), str(self.stock / 'web/src/plugins/registry.ts'),
                                 str(HERE / 'dashboard/dist/index.js')], cwd=HERE)
        self.assertEqual(receipt['registered'], 1)
        self.assertEqual(receipt['root'], 'div')
        self.assertEqual(receipt['calls'], ['/api/plugins/wiretap/health'])

    def test_desktop_reconciliation_materializes_native_wiretap_entry(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node required for native Desktop filesystem contract check')
        module = self.stock / 'apps/desktop/electron/desktop-plugins-root.ts'
        if not module.exists():
            self.skipTest('This Hermes checkout has no Desktop plugin host')
        probe = self.root / 'desktop-probe.mjs'
        probe.write_text(_DESKTOP_PROBE, encoding='utf-8')
        receipt = self.run_json([node, '--experimental-strip-types', str(probe), str(module),
                                 str(self.root / 'desktop'), str(HERE)], cwd=HERE)
        self.assertEqual(receipt['materialized'], ['contract-positive', 'wiretap'])
        self.assertTrue(receipt['wiretapNativeEntry'])

    def test_native_desktop_loader_registers_page_and_scoped_api(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node required for native Desktop runtime contract check')
        loader = self.stock / 'apps/desktop/src/contrib/runtime-loader.ts'
        if not loader.exists():
            self.skipTest('This Hermes checkout has no Desktop runtime loader')
        probe = self.root / 'desktop-loader-probe.mjs'
        probe.write_text(_DESKTOP_LOADER_PROBE, encoding='utf-8')
        receipt = self.run_json([node, '--experimental-vm-modules', str(probe),
                                 str(self.stock / 'apps/desktop/src/sdk/runtime.ts'), str(loader),
                                 str(self.stock / 'apps/desktop/src/contrib/plugin.ts'),
                                 str(self.stock / 'apps/desktop/src/api/plugins.ts'),
                                 str(HERE / 'desktop/plugin.js')], cwd=HERE)
        self.assertEqual(receipt['positive'], 'positive')
        self.assertEqual(receipt['wiretap'], 'wiretap')
        self.assertEqual(receipt['route'], '/wiretap')
        self.assertEqual(receipt['root'], 'div')
        self.assertTrue(receipt['profileRemount'])
        self.assertTrue(receipt['connectionRemount'])
        self.assertEqual(receipt['palette'], ['/wiretap'])
        self.assertTrue(receipt['styleLifecycle'])

    def test_native_bundle_is_current_and_passes_stock_desktop_admission(self):
        result = subprocess.run([sys.executable, str(HERE / 'desktop/build.py'), '--check'],
                                cwd=HERE, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        from hermes_cli.plugin_validate_desktop import desktop_surface_hits
        self.assertEqual(desktop_surface_hits(HERE), [])

    def test_native_full_inspector_and_calls_render_with_real_backend_payloads(self):
        node = shutil.which('node')
        candidates = [os.environ.get('WIRETAP_JSDOM_DIR'), self.stock, HERE.parent.parent]
        dependency_root = next((Path(p) for p in candidates if p and
                                (Path(p) / 'node_modules/jsdom').is_dir() and
                                (Path(p) / 'node_modules/react-dom').is_dir()), None)
        if not node or dependency_root is None:
            self.skipTest('Node, jsdom, and react-dom required for native DOM integration')
        receipt = self.run_json([sys.executable, str(Path(__file__).resolve()), '--headless-probe',
                                 str(self.root / 'native-backend')], cwd=HERE)
        self.assertTrue(receipt['headless'])
        fixtures = self.root / 'native-payloads.json'
        fixtures.write_text(json.dumps(receipt['native_fixtures']), encoding='utf-8')
        probe = self.root / 'native-render-probe.mjs'
        probe.write_text(_NATIVE_RENDER_PROBE, encoding='utf-8')
        result = self.run_json([node, '--experimental-vm-modules', str(probe),
                                str(HERE / 'desktop/plugin.js'), str(dependency_root), str(fixtures)], cwd=HERE)
        self.assertTrue(result['inspector'])
        self.assertTrue(result['callsView'])
        for behavior in ('palette', 'styleLifecycle', 'renderedTheme', 'proxyBanner', 'hashLinks', 'storage'):
            self.assertTrue(result[behavior], behavior)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('--classic-probe', '--headless-probe'):
        _classic_probe(Path(sys.argv[2]), headless=sys.argv[1] == '--headless-probe')
    else:
        unittest.main()
