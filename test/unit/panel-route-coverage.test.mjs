import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const serverSrc = [
  fs.readFileSync(path.join(root, 'src/lib/admin/panel-routes.mjs'), 'utf8'),
  fs.readFileSync(path.join(root, 'src/server.mjs'), 'utf8'),
].join('\n')

function serverPanelHandlers(src) {
  const handlers = []
  const exact = /req\.method === '(GET|POST|PUT|PATCH|DELETE)' && p === '(\/api\/panel\/[^']+)'/g
  let match
  while ((match = exact.exec(src))) {
    const method = match[1]
    const pathName = match[2]
    handlers.push({ method, matchPath: (p) => p === pathName })
  }
  const regex = /req\.method === '(GET|POST|PUT|PATCH|DELETE)' && \/\^(\\\/api\\\/panel\\\/.+?)\$\/\.test\(p\)/g
  while ((match = regex.exec(src))) {
    try {
      const method = match[1]
      const re = new RegExp('^' + match[2].replace(/\\\//g, '/') + '$')
      handlers.push({ method, matchPath: (p) => re.test(p) })
    } catch {}
  }
  return handlers
}

/** Panel routes the kin-console web UI calls. Sourced from the UI, asserted against the server only. */
const PANEL_ROUTE_SAMPLES = [
  ['POST', '/api/panel/login'],
  ['POST', '/api/panel/logout'],
  ['GET', '/api/panel/dashboard'],
  ['GET', '/api/panel/database/metrics'],
  ['GET', '/api/panel/version'],
  ['GET', '/api/panel/changelog'],
  ['POST', '/api/panel/update'],
  ['GET', '/api/panel/vms'],
  ['GET', '/api/panel/vms/vm-01'],
  ['PATCH', '/api/panel/vms/vm-01'],
  ['DELETE', '/api/panel/vms/vm-01'],
  ['POST', '/api/panel/vms/vm-01/schedulable'],
  ['POST', '/api/panel/vms/vm-01/cooldown/clear'],
  ['POST', '/api/panel/vms/vm-01/circuit/reset'],
  ['POST', '/api/panel/vms/vm-01/reload'],
  ['POST', '/api/panel/vms/vm-01/collect-identity'],
  ['POST', '/api/panel/vms/vm-01/probe'],
  ['POST', '/api/panel/vms/vm-01/test-chat'],
  ['GET', '/api/panel/vms/vm-01/seed-settings'],
  ['PUT', '/api/panel/vms/vm-01/seed-settings'],
  ['GET', '/api/panel/vms/vm-01/official-cc-bootstrap'],
  ['POST', '/api/panel/vms/vm-01/official-cc-bootstrap'],
  ['POST', '/api/panel/vms/vm-01/reconcile-fingerprint'],
  ['POST', '/api/panel/vms/vm-01/oauth/generate-auth-url'],
  ['POST', '/api/panel/vms/vm-01/oauth/exchange-code'],
  ['POST', '/api/panel/vms/vm-01/oauth/to-setup-token'],
  ['POST', '/api/panel/vms/vm-01/oauth/refresh'],
  ['GET', '/api/panel/vms/vm-01/oauth/credential'],
  ['PUT', '/api/panel/vms/vm-01/oauth/credential'],
  ['POST', '/api/panel/vms/vm-01/start'],
  ['POST', '/api/panel/vms/vm-01/stop'],
  ['POST', '/api/panel/vms/vm-01/activate'],
  ['POST', '/api/panel/vms/vm-01/reset'],
  ['POST', '/api/panel/vms/vm-01/reset-fingerprint'],
  ['POST', '/api/panel/vms/vm-01/allocate-proxy'],
  ['POST', '/api/panel/vms/create'],
  ['GET', '/api/panel/vms/create-options'],
  ['GET', '/api/panel/vms/vm-01/package'],
  ['PUT', '/api/panel/vms/vm-01/package'],
  ['POST', '/api/panel/vms/package'],
  ['POST', '/api/panel/vms/import'],
  ['POST', '/api/panel/vms/fleet-update'],
  ['GET', '/api/panel/wrap-cli'],
  ['POST', '/api/panel/wrap-cli/sync'],
  ['POST', '/api/panel/wrap-cli/make'],
  ['POST', '/api/panel/wrap-cli/kernel'],
  ['POST', '/api/panel/wrap-cli/kernel/release'],

  ['POST', '/api/panel/vms/vm-01/wrap-cli/promote'],
  ['POST', '/api/panel/vms/vm-01/wrap-cli/repair'],

  ['POST', '/api/panel/vms/slot-policy'],
  ['POST', '/api/panel/probe'],
  ['GET', '/api/panel/health-probe'],
  ['POST', '/api/panel/health-probe'],
  ['GET', '/api/panel/usage-probe'],
  ['POST', '/api/panel/usage-probe'],
  ['GET', '/api/panel/routing'],
  ['PUT', '/api/panel/routing'],
  ['GET', '/api/panel/distill'],
  ['PUT', '/api/panel/distill'],
  ['GET', '/api/panel/model-policy'],
  ['PUT', '/api/panel/model-policy'],
  ['POST', '/api/panel/model-policy/reset'],
  ['POST', '/api/panel/model-policy/sync-worker'],
  ['GET', '/api/panel/notify'],
  ['POST', '/api/panel/notify/check'],
  ['POST', '/api/panel/notify/test'],
  ['GET', '/api/panel/vm-pools'],
  ['POST', '/api/panel/vm-pools'],
  ['PATCH', '/api/panel/vm-pools/pool_abcd1234'],
  ['DELETE', '/api/panel/vm-pools/pool_abcd1234'],
  ['GET', '/api/panel/api-keys'],
  ['POST', '/api/panel/api-keys'],
  ['PATCH', '/api/panel/api-keys/k1'],
  ['DELETE', '/api/panel/api-keys/k1'],
  ['POST', '/api/panel/api-keys/k1/reset-quota'],
  ['POST', '/api/panel/api-keys/k1/reveal'],
  ['POST', '/api/panel/api-keys/k1/rotate'],
  ['GET', '/api/panel/api-keys/k1/stats'],
  ['GET', '/api/panel/api-endpoints'],
  ['POST', '/api/panel/api-endpoints'],
  ['PATCH', '/api/panel/api-endpoints/e1'],
  ['DELETE', '/api/panel/api-endpoints/e1'],
  ['POST', '/api/panel/api-endpoints/e1/fetch-models'],
  ['POST', '/api/panel/api-endpoints/e1/keys'],
  ['DELETE', '/api/panel/api-endpoints/e1/keys/k1'],
  ['GET', '/api/panel/proxies'],
  ['POST', '/api/panel/proxies/import'],
  ['POST', '/api/panel/proxies/probe'],
  ['POST', '/api/panel/proxies/geo'],
  ['PUT', '/api/panel/proxies/config'],
  ['POST', '/api/panel/proxies/p1/probe'],
  ['POST', '/api/panel/proxies/p1/geo'],
  ['POST', '/api/panel/proxies/p1/enable'],
  ['POST', '/api/panel/proxies/p1/disable'],
  ['POST', '/api/panel/proxies/p1/bind'],
  ['POST', '/api/panel/proxies/p1/unbind'],
  ['POST', '/api/panel/model-policy/sync-codex'],
  ['GET', '/api/panel/users'],
  ['POST', '/api/panel/users'],
  ['PATCH', '/api/panel/users/u1'],
  ['DELETE', '/api/panel/users/u1'],
  ['GET', '/api/panel/usage-logs'],
  ['GET', '/api/panel/usage-logs/summary'],
  ['GET', '/api/panel/usage-logs/filter-options'],
  ['GET', '/api/panel/usage-logs/session-suggestions'],
  ['GET', '/api/panel/usage-logs/active-sessions'],
  ['GET', '/api/panel/usage-logs/overview'],
  ['GET', '/api/panel/statistics'],
  ['GET', '/api/panel/statistics/leaderboard'],
]

test('panel route samples all have server handlers', () => {
  const handlers = serverPanelHandlers(serverSrc)
  assert.ok(handlers.length > 50, `expected panel handlers, got ${handlers.length}`)
  const missing = []
  for (const [method, sample] of PANEL_ROUTE_SAMPLES) {
    const ok = handlers.some((handler) => handler.method === method && handler.matchPath(sample))
    if (!ok) missing.push(`${method} ${sample}`)
  }
  assert.deepEqual(missing, [])
})

test('ACL schedule POSTs still have handlers', () => {
  assert.match(serverSrc, /cooldown\\\/clear/)
  assert.match(serverSrc, /clearVmCooldown/)
  assert.match(serverSrc, /\/schedulable\$/)
})

test('settings save imports public routing notify helpers', () => {
  const routes = fs.readFileSync(path.join(root, 'src/lib/admin/panel-routes.mjs'), 'utf8')
  assert.match(
    routes,
    /import\s*\{[^}]*publicNotifyConfig[^}]*publicRoutingNotify[^}]*\}\s*from\s*['"]\.\/notify\.mjs['"]/,
  )
})

test('PUT proxy restarts kin-egress when connection or domain_forward changes', () => {
  const routes = fs.readFileSync(path.join(root, 'src/lib/admin/panel-routes.mjs'), 'utf8')
  assert.match(routes, /result\.domain_forward_changed \|\| result\.connection_changed/)
})

async function exchangeRouteHarness({
  groveSettings,
  error,
  body = {},
  commitResult = { ok: true },
  scopeProfile,
} = {}) {
  const routes = fs.readFileSync(path.join(root, 'src/lib/admin/panel-routes.mjs'), 'utf8')
  const start = routes.indexOf(
    "      if (req.method === 'POST' && /^\\/api\\/panel\\/vms\\/[^/]+\\/oauth\\/exchange-code$/.test(p)) {",
  )
  const end = routes.indexOf(
    "      if (req.method === 'GET' && /^\\/api\\/panel\\/vms\\/[^/]+\\/oauth\\/credential$/.test(p)) {",
    start,
  )
  assert.ok(start > 0 && end > start)
  const response = {}
  const exchanges = []
  const commits = []
  const oauth = {
    access_token: 'route-access',
    refresh_token: 'route-refresh',
    expires_at: 2000000000,
    email: 'route@example.test',
    account_uuid: 'route-account',
    org_uuid: 'route-org',
    source: 'oauth-auth-url',
    flavor: 'cai',
    ...(groveSettings ? { grove_settings: groveSettings } : {}),
    ...(scopeProfile ? { scope_profile: scopeProfile } : {}),
  }
  const bindings = {
    req: { method: 'POST' },
    res: {},
    p: '/api/panel/vms/vm-01/oauth/exchange-code',
    cfg: { paths: { project: root } },
    ctx: { routingConfig: {} },
    path,
    fs: {
      existsSync: () => true,
      readFileSync: () => JSON.stringify({ id: 'vm-01', claude: {} }),
    },
    readBody: async () => ({ session_id: 'route-session', code: 'route-code', ...body }),
    requireSlotProxy: () => ({ ok: true, proxyUrl: '' }),
    isCodexVm: () => false,
    looksLikeOfficialSetupToken: () => false,
    normalizeOauthFlavor: () => 'cai',
    SETUP_TOKEN_FLAVOR: 'claude_setup_token',
    exchangeAuthCode: async (opts) => {
      exchanges.push(opts)
      if (error) throw error
      return oauth
    },
    enrichOauthIdentity: async (value) => value,
    commitImportedOauth: async (opts) => {
      commits.push(opts)
      opts.existing.claude = { email: opts.oauth.email, has_refresh: !!opts.oauth.refresh_token }
      return commitResult
    },
    summarizeVm: (value) => ({ id: value.id }),
    panel: { ok: (data) => ({ ok: true, data }) },
    json: (_res, status, payload) => {
      response.status = status
      response.body = payload
      return true
    },
  }
  const run = new Function(...Object.keys(bindings), `return (async () => {${routes.slice(start, end)}})()`)
  await run(...Object.values(bindings))
  return { response, exchanges, commits, oauth }
}

test('exchange-code route forwards only internal Grove metadata and still uses the original commit contract', async () => {
  for (const groveSettings of [undefined, { status: 'skipped', reason: 'disabled_by_operator' }]) {
    const { response, exchanges, commits, oauth } = await exchangeRouteHarness({
      groveSettings,
      body: {
        name: 'slot-name',
        skipGroveSettings: true,
        skip_grove_settings: true,
        tokenUrls: ['https://evil.test/v1/oauth/token'],
        token_urls: ['https://evil.test/v1/oauth/token'],
        redirect_uri: 'https://evil.test/callback',
        grove_settings: { status: 'privacy_updated' },
      },
    })
    assert.equal(response.status, 200)
    assert.equal(response.body.ok, true)
    assert.deepEqual(exchanges, [{ sessionId: 'route-session', code: 'route-code', proxyUrl: '', vmId: 'vm-01' }])
    assert.equal(commits.length, 1)
    assert.equal(commits[0].oauth, oauth)
    assert.equal(commits[0].vmId, 'vm-01')
    assert.equal(commits[0].vmPath, path.join(root, 'vms', 'vm-01.json'))
    assert.equal(commits[0].source, oauth.source)
    assert.equal(commits[0].name, 'slot-name')
    assert.equal(response.body.data.oauth_email, oauth.email)
    assert.equal(response.body.data.has_refresh, true)
    assert.equal(Object.hasOwn(response.body.data, 'grove_settings'), !!groveSettings)
    if (groveSettings) assert.deepEqual(response.body.data.grove_settings, groveSettings)
    assert.equal(JSON.stringify(response.body).includes('privacy_updated'), false)
    assert.equal(JSON.stringify(response.body).includes('route-access'), false)
    assert.equal(JSON.stringify(response.body).includes('route-refresh'), false)
  }
})

test('exchange-code route skips official Claude Code first-run only for voice grants', async () => {
  for (const [scopeProfile, skip] of [
    ['voice', true],
    ['default', false],
    [undefined, false],
  ]) {
    const { response, commits } = await exchangeRouteHarness({ scopeProfile })
    assert.equal(response.status, 200)
    assert.equal(commits.length, 1)
    assert.equal(commits[0].skipOfficialCc, skip)
  }
})

test('exchange-code route accepts only safe internal HTTP statuses and never turns upstream 401 into panel logout', async () => {
  for (const httpStatus of [400, 409, 502, 504, 401, 403, 404, 500, '400', undefined]) {
    const error = Object.assign(new Error('Filtered upstream failure'), { code: 'bootstrap_failed', httpStatus })
    const { response, commits } = await exchangeRouteHarness({ error })
    assert.equal(response.status, [400, 409, 502, 504].includes(httpStatus) ? httpStatus : 502)
    assert.equal(response.body.ok, false)
    assert.equal(response.body.error.code, 'bootstrap_failed')
    assert.equal(commits.length, 0)
  }
  const { response } = await exchangeRouteHarness({
    error: Object.assign(new Error('Session expired'), { code: 'session_expired' }),
  })
  assert.equal(response.status, 400)
})

test('exchange-code route preserves commit rejection rather than returning a fake success', async () => {
  const failure = { code: 'credential_import_failed', message: 'Commit failed' }
  const { response, commits } = await exchangeRouteHarness({ commitResult: { ok: false, status: 502, error: failure } })
  assert.equal(commits.length, 1)
  assert.equal(response.status, 502)
  assert.equal(response.body.ok, false)
  assert.deepEqual(response.body.error, failure)
})

test('panel authentication, ACL and VM ownership guards still precede authorization-code exchange', () => {
  const routes = fs.readFileSync(path.join(root, 'src/lib/admin/panel-routes.mjs'), 'utf8')
  const exchange = routes.indexOf('/oauth\\/exchange-code$/.test(p)')
  for (const guard of [
    'if (!requireAuth(req, res)) return',
    'const isPanelOperator =',
    'const gate = authorizePanelRoute(',
    'denyIfUserMissesVm(req, res, {',
  ]) {
    const index = routes.indexOf(guard)
    assert.ok(index > 0 && index < exchange, guard)
  }
})
