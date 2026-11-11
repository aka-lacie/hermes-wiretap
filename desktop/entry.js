// Native Desktop source template. Run python3 desktop/build.py after renderer/CSS edits.
// The distributed plugin.js is self-contained: Desktop only permits SDK/react imports.
import * as React from 'react';
import { host, useValue, PALETTE_AREA, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk';

/* SHARED_RENDERER */
const WIRETAP_CSS = /* SHARED_STYLES */ '';

function readDesktopQuery() {
  try {
    // Only Wiretap's hash-route owns these fields; ignore the app's outer query
    // and other routes, including an empty hash during startup.
    const hash = window.location.hash || '';
    const at = hash.indexOf('?');
    if (at < 0 || hash.slice(0, at) !== '#/wiretap') return {};
    const q = new URLSearchParams(hash.slice(at + 1));
    const view = q.get('view');
    return { view: view === 'inspector' || view === 'telemetry' ? view : null,
      session: q.get('session'), row: q.get('row'), tab: q.get('tab'), mode: q.get('mode'), call: q.get('call') };
  } catch (_) { return {}; }
}

function injectStyle(ctx) {
  // Replace stale copies, rather than sharing ownership with an older instance:
  // even a late disposer from that instance cannot remove the new stylesheet.
  document.head.querySelectorAll('style[data-wiretap]').forEach(el => el.remove());
  const style = document.createElement('style');
  style.setAttribute('data-wiretap', '');
  style.textContent = WIRETAP_CSS;
  document.head.appendChild(style);
  ctx.onDispose(() => style.remove());
}

export default {
  id: 'wiretap',
  name: 'Wiretap',
  description: 'Session & Wire Inspector and Calls & Cache, using the active backend’s Wiretap API.',
  defaultEnabled: true,
  register(ctx) {
    injectStyle(ctx);
    const prefix = '/api/plugins/wiretap';
    const ui = createWiretapUI({
      React,
      hooks: React,
      host: 'desktop',
      storage: ctx.storage,
      readQuery: readDesktopQuery,
      fetchJSON(url) {
        if (!url.startsWith(prefix + '/')) {
          return Promise.reject(new Error('Wiretap refused an API outside its namespace'));
        }
        // The host supplies credentials, backend connection, and active profile.
        // No direct fetch, token handling, server addresses, or iframe.
        return ctx.rest(url.slice(prefix.length));
      },
    });
    function WiretapPage() {
      const profile = useValue(host.state.profile);
      const connection = useValue(host.state.connectionId);
      // Dispose the old inspector (and its outstanding responses) on backend/profile changes.
      const scope = JSON.stringify([connection, profile]);
      return React.createElement(ui.Page, { key: scope });
    }
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: '/wiretap' },
        render: () => React.createElement(WiretapPage) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, order: 80,
        data: { path: '/wiretap', label: 'Wiretap', codicon: 'pulse' } },
      { id: 'open', area: PALETTE_AREA,
        data: { id: 'wiretap.open', label: 'Open Wiretap',
          keywords: ['wiretap', 'wire', 'cache', 'telemetry', 'calls', 'inspector'],
          run: () => host.navigate('/wiretap') } },
    ]);
  },
};
