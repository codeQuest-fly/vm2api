import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import childProcess from 'node:child_process'
import { EventEmitter } from 'node:events'
import { syncBuiltinESMExports } from 'node:module'
import { PassThrough } from 'node:stream'
import { Response } from 'node-fetch'
import { sessionKeyToOAuth } from '../../src/lib/oauth/cookie-auth.mjs'
import { CLAUDE_CLI_BOOTSTRAP_URL } from '../../src/lib/oauth/oauth-identity.mjs'
import {
  generateAuthUrl,
  exchangeAuthCode,
  peekAuthUrlSession,
  resetAuthUrlSessions,
  buildAuthorizationURL,
  CLIENT_ID,
  AUTHORIZE_URL,
  REDIRECT_URI,
  SCOPE_OAUTH,
  OAUTH_FLAVORS,
} from '../../src/lib/oauth/oauth-auth-url.mjs'

test('generateAuthUrl refuses an unbound VM but accepts local egress as direct', () => {
  resetAuthUrlSessions()
  assert.throws(() => generateAuthUrl({}), /vm_id required/)
  assert.throws(() => generateAuthUrl({ vmId: 'vm-01' }), /SOCKS5/)
  assert.throws(() => generateAuthUrl({ vmId: 'vm-01', proxyUrl: null }), /SOCKS5/)
  const out = generateAuthUrl({ vmId: 'vm-01', proxyUrl: '' })
  assert.equal(peekAuthUrlSession(out.session_id).proxyUrl, '')
})

test('generateAuthUrl builds Claude authorize URL and stores PKCE', () => {
  resetAuthUrlSessions()
  const out = generateAuthUrl({ vmId: 'vm-01', proxyUrl: 'socks5h://127.0.0.1:1080' })
  assert.match(out.auth_url, new RegExp('^' + AUTHORIZE_URL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(out.auth_url, /code=true/)
  assert.match(out.auth_url, new RegExp('client_id=' + CLIENT_ID))
  assert.match(out.auth_url, /response_type=code/)
  assert.match(out.auth_url, /code_challenge_method=S256/)
  assert.ok(out.auth_url.includes(encodeURIComponent(REDIRECT_URI)))
  assert.ok(out.auth_url.includes(encodeURIComponent(SCOPE_OAUTH).replace(/%20/g, '+')))
  assert.equal(out.vm_id, 'vm-01')
  assert.ok(out.session_id)
  assert.ok(out.expires_at > Date.now())
  const session = peekAuthUrlSession(out.session_id)
  assert.ok(session)
  assert.equal(session.vmId, 'vm-01')
  assert.ok(session.codeVerifier)
  assert.ok(session.state)
  assert.equal(out.flavor, 'cai')
  assert.equal(session.flavor, 'cai')
  assert.equal(session.redirectUri, REDIRECT_URI)
})

test('generateAuthUrl claude_code uses official authorize and callback', () => {
  resetAuthUrlSessions()
  const spec = OAUTH_FLAVORS.claude_code
  const out = generateAuthUrl({
    vmId: 'vm-01',
    proxyUrl: 'socks5h://127.0.0.1:1080',
    flavor: 'claude_code',
  })
  assert.equal(out.flavor, 'claude_code')
  assert.match(out.auth_url, /^https:\/\/claude\.ai\/oauth\/authorize\?code=true/)
  assert.ok(out.auth_url.includes(encodeURIComponent(spec.redirectUri)))
  assert.ok(out.auth_url.includes(encodeURIComponent(spec.scope).replace(/%20/g, '+')))
  assert.ok(!out.auth_url.includes('cai/oauth'))
  const session = peekAuthUrlSession(out.session_id)
  assert.equal(session.flavor, 'claude_code')
  assert.equal(session.redirectUri, spec.redirectUri)
  assert.deepEqual(session.tokenUrls, spec.tokenUrls)
  assert.equal(session.source, 'oauth-claude-code')
})

test('generateAuthUrl setup_token uses full scope on CAI but keeps setup-token flavor', () => {
  resetAuthUrlSessions()
  const spec = OAUTH_FLAVORS.setup_token
  const out = generateAuthUrl({
    vmId: 'vm-01',
    proxyUrl: 'socks5h://127.0.0.1:1080',
    flavor: 'setup_token',
  })
  assert.equal(out.flavor, 'setup_token')
  assert.match(out.auth_url, /^https:\/\/claude\.com\/cai\/oauth\/authorize\?code=true/)
  assert.ok(out.auth_url.includes(encodeURIComponent(spec.scope).replace(/%20/g, '+')))
  assert.ok(out.auth_url.includes('user%3Aprofile'))
  const session = peekAuthUrlSession(out.session_id)
  assert.equal(session.flavor, 'setup_token')
  assert.equal(session.scope, spec.scope)
  assert.equal(session.source, 'oauth-setup-token')
})

test('voice scope profile swaps only the scope on every auth-link flavor', () => {
  const voiceScope = 'scope=org%3Acreate_api_key+user%3Aprofile+user%3Avoice+user%3Amcp_servers&'
  for (const flavor of ['cai', 'claude_code', 'setup_token']) {
    resetAuthUrlSessions()
    const spec = OAUTH_FLAVORS[flavor]
    const out = generateAuthUrl({
      vmId: 'vm-01',
      proxyUrl: 'socks5h://127.0.0.1:1080',
      flavor,
      scopeProfile: 'voice',
    })
    assert.equal(out.flavor, flavor)
    assert.equal(out.scope_profile, 'voice')
    assert.ok(out.auth_url.startsWith(`${spec.authorizeUrl}?code=true`), out.auth_url)
    assert.ok(out.auth_url.includes(encodeURIComponent(spec.redirectUri)))
    assert.ok(out.auth_url.includes(voiceScope), out.auth_url)
    assert.ok(!out.auth_url.includes('user%3Ainference'))
    const session = peekAuthUrlSession(out.session_id)
    assert.equal(session.flavor, flavor)
    assert.equal(session.scopeProfile, 'voice')
    assert.equal(session.source, spec.source)
  }
})

test('unknown or missing scope profile keeps the flavor default scope', () => {
  for (const scopeProfile of [undefined, '', 'default', 'inference']) {
    resetAuthUrlSessions()
    const out = generateAuthUrl({ vmId: 'vm-01', proxyUrl: '', flavor: 'setup_token', scopeProfile })
    assert.equal(out.scope_profile, 'default')
    assert.equal(peekAuthUrlSession(out.session_id).scope, OAUTH_FLAVORS.setup_token.scope)
  }
})

test('buildAuthorizationURL matches sub2api parameter order', () => {
  const url = buildAuthorizationURL('st', 'ch')
  assert.ok(url.startsWith(`${AUTHORIZE_URL}?code=true&client_id=${CLIENT_ID}&response_type=code`))
})

test('exchangeAuthCode rejects missing / mismatched session', async () => {
  resetAuthUrlSessions()
  await assert.rejects(
    () => exchangeAuthCode({ sessionId: 'missing', code: 'abc', proxyUrl: 'socks5h://127.0.0.1:1' }),
    /过期/,
  )
  const out = generateAuthUrl({ vmId: 'vm-01', proxyUrl: 'socks5h://127.0.0.1:1080' })
  await assert.rejects(
    () =>
      exchangeAuthCode({
        sessionId: out.session_id,
        code: 'abc',
        proxyUrl: 'socks5h://127.0.0.1:1080',
        vmId: 'vm-02',
      }),
    /不匹配/,
  )
})

test('fake exchange writes tokens without network', async () => {
  resetAuthUrlSessions()
  process.env.KIN_FAKE_SESSION_OAUTH = '1'
  const out = generateAuthUrl({ vmId: 'vm-01', proxyUrl: 'socks5h://127.0.0.1:1080' })
  const cred = await exchangeAuthCode({
    sessionId: out.session_id,
    code: 'pasted-code',
    proxyUrl: 'socks5h://127.0.0.1:1080',
    vmId: 'vm-01',
  })
  assert.equal(cred.source, 'KIN_FAKE_SESSION_OAUTH')
  assert.match(cred.access_token, /^sk-ant-oat01-FAKE-AUTH-URL/)
  assert.equal(peekAuthUrlSession(out.session_id), null)
  const cc = generateAuthUrl({
    vmId: 'vm-01',
    proxyUrl: 'socks5h://127.0.0.1:1080',
    flavor: 'claude_code',
  })
  const ccCred = await exchangeAuthCode({
    sessionId: cc.session_id,
    code: 'pasted-code',
    proxyUrl: 'socks5h://127.0.0.1:1080',
    vmId: 'vm-01',
  })
  assert.equal(ccCred.flavor, 'claude_code')
  delete process.env.KIN_FAKE_SESSION_OAUTH
})

const exchangedToken = {
  access_token: 'sk-ant-oat01-STRICT-EXCHANGE',
  refresh_token: 'sk-ant-ort01-STRICT-EXCHANGE',
  token_type: 'Bearer',
  expires_in: 28800,
  scope: 'user:profile user:inference',
}
const exchangedIdentity = {
  oauth_account: {
    account_email: 'strict@example.test',
    account_uuid: 'acct-strict',
    organization_uuid: 'org-strict',
  },
}

function oauthResponse(status, body) {
  return new Response(JSON.stringify(body), { status })
}

function isolateOAuthEnv(t) {
  resetAuthUrlSessions()
  const keys = ['KIN_FAKE_SESSION_OAUTH', 'VM2API_SKIP_GROVE_SETTINGS', 'KIN_OAUTH_AUTH_BIN']
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]))
  delete process.env.KIN_FAKE_SESSION_OAUTH
  delete process.env.VM2API_SKIP_GROVE_SETTINGS
  t.after(() => {
    resetAuthUrlSessions()
    for (const key of keys) {
      if (previous[key] === undefined) delete process.env[key]
      else process.env[key] = previous[key]
    }
  })
}

function mockLegacyService(t) {
  const payloads = []
  process.env.KIN_OAUTH_AUTH_BIN = process.execPath
  const spawnMock = t.mock.method(childProcess, 'spawn', (file, args) => {
    assert.equal(file, process.execPath)
    assert.deepEqual(args, [])
    const child = new EventEmitter()
    child.stdout = new PassThrough()
    child.stderr = new PassThrough()
    child.stdin = {
      end(input) {
        payloads.push(JSON.parse(input))
        queueMicrotask(() => {
          child.stdout.end(
            JSON.stringify({
              ok: true,
              credential: {
                ...exchangedToken,
                email: 'legacy@example.test',
                account_uuid: 'acct-legacy',
                org_uuid: 'org-legacy',
              },
            }) + '\n',
          )
          child.stderr.end()
          child.emit('close', 0)
        })
      },
    }
    return child
  })
  syncBuiltinESMExports()
  t.after(() => {
    spawnMock.mock.restore()
    syncBuiltinESMExports()
  })
  return payloads
}

test('skip-Grove code exchange preserves all flavor PKCE, redirect, provider-state and metadata contracts', async (t) => {
  isolateOAuthEnv(t)
  for (const [flavor, returnedState, scopeProfile = 'default'] of [
    ['cai', 'provider-cai-state'],
    ['claude_code', 'provider-cc-state'],
    ['cai', undefined],
    ['claude_code', undefined],
    ['setup_token', 'session'],
    ['setup_token', undefined],
    ['setup_token', 'session', 'voice'],
    ['cai', 'provider-cai-state', 'voice'],
    ['claude_code', undefined, 'voice'],
  ]) {
    await t.test(`${flavor}/${scopeProfile}: ${returnedState || 'no suffix'}`, async () => {
      const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '', flavor, scopeProfile })
      const session = peekAuthUrlSession(generated.session_id)
      const url = new URL(generated.auth_url)
      const state = returnedState === 'session' ? session.state : returnedState
      const seen = []
      const result = await exchangeAuthCode({
        sessionId: generated.session_id,
        code: state ? `strict-code#${state}` : 'strict-code',
        vmId: 'vm-strict',
        skipGroveSettings: true,
        fetchImpl: async (requestUrl, init) => {
          seen.push({ url: requestUrl, init })
          assert.equal(session.exchanging, true)
          if (requestUrl === CLAUDE_CLI_BOOTSTRAP_URL) {
            assert.equal(peekAuthUrlSession(generated.session_id), null)
            return oauthResponse(200, exchangedIdentity)
          }
          const body = JSON.parse(init.body)
          const challenge = crypto.createHash('sha256').update(body.code_verifier).digest('base64url')
          assert.equal(body.code, 'strict-code')
          assert.equal(body.client_id, CLIENT_ID)
          assert.equal(body.grant_type, 'authorization_code')
          assert.equal(challenge, url.searchParams.get('code_challenge'))
          assert.equal(body.redirect_uri, OAUTH_FLAVORS[flavor].redirectUri)
          const expectedState = flavor === 'setup_token' ? session.state : state
          assert.equal(body.state, expectedState)
          if (expectedState === undefined) assert.equal(Object.hasOwn(body, 'state'), false)
          return oauthResponse(200, exchangedToken)
        },
      })
      assert.equal(seen.length, 2)
      assert.equal(seen[0].url, OAUTH_FLAVORS[flavor].tokenUrls[0])
      assert.equal(seen.filter(({ init }) => init.method === 'PATCH').length, 0)
      assert.equal(result.access_token, exchangedToken.access_token)
      assert.equal(result.refresh_token, exchangedToken.refresh_token)
      assert.equal(result.scope, exchangedToken.scope)
      assert.equal(result.expires_in, exchangedToken.expires_in)
      assert.equal(result.email, 'strict@example.test')
      assert.equal(result.source, OAUTH_FLAVORS[flavor].source)
      assert.equal(result.flavor, flavor)
      assert.equal(result.scope_profile, scopeProfile)
      assert.deepEqual(result.grove_settings, { status: 'skipped', reason: 'disabled_by_operator' })
      assert.equal(peekAuthUrlSession(generated.session_id), null)
      assert.equal(session.exchanging, false)
    })
  }
})

test('skip-Grove voice exchange keeps the granted voice scope without user:inference', async (t) => {
  isolateOAuthEnv(t)
  const generated = generateAuthUrl({ vmId: 'vm-voice', proxyUrl: '', flavor: 'setup_token', scopeProfile: 'voice' })
  const voiceScope = 'user:mcp_servers user:profile user:voice'
  const seen = []
  const result = await exchangeAuthCode({
    sessionId: generated.session_id,
    code: `voice-code#${peekAuthUrlSession(generated.session_id).state}`,
    vmId: 'vm-voice',
    skipGroveSettings: true,
    fetchImpl: async (url, init) => {
      seen.push({ url, init })
      if (url === CLAUDE_CLI_BOOTSTRAP_URL) return oauthResponse(200, exchangedIdentity)
      return oauthResponse(200, { ...exchangedToken, scope: voiceScope })
    },
  })
  assert.equal(seen.filter(({ init }) => init.method === 'PATCH').length, 0)
  assert.equal(result.flavor, 'setup_token')
  assert.equal(result.scope_profile, 'voice')
  assert.equal(result.source, 'oauth-setup-token')
  assert.equal(result.scope, voiceScope)
  assert.equal(result.refresh_token, exchangedToken.refresh_token)
})

test('enabled server environment values select strict exchange without the fake-session branch', async (t) => {
  isolateOAuthEnv(t)
  for (const setting of ['1', 'true']) {
    process.env.VM2API_SKIP_GROVE_SETTINGS = setting
    const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '' })
    const seen = []
    const result = await exchangeAuthCode({
      sessionId: generated.session_id,
      code: 'strict-code#provider-state',
      vmId: 'vm-strict',
      fetchImpl: async (url, init) => {
        seen.push({ url, init })
        return oauthResponse(200, url === CLAUDE_CLI_BOOTSTRAP_URL ? exchangedIdentity : exchangedToken)
      },
    })
    assert.equal(seen.length, 2)
    assert.equal(result.access_token, exchangedToken.access_token)
    assert.notEqual(result.source, 'KIN_FAKE_SESSION_OAUTH')
    assert.equal(result.grove_settings.status, 'skipped')
  }
})

test('default/disabled flag retains the legacy service exchange and has no skip metadata', async (t) => {
  isolateOAuthEnv(t)
  const payloads = mockLegacyService(t)
  for (const setting of [undefined, '0', 'false', 'yes', 'TRUE']) {
    if (setting === undefined) delete process.env.VM2API_SKIP_GROVE_SETTINGS
    else process.env.VM2API_SKIP_GROVE_SETTINGS = setting
    const generated = generateAuthUrl({ vmId: 'vm-legacy', proxyUrl: '', flavor: 'claude_code' })
    const result = await exchangeAuthCode({
      sessionId: generated.session_id,
      code: 'legacy-code#legacy-provider-state',
      vmId: 'vm-legacy',
    })
    assert.equal(result.email, 'legacy@example.test')
    assert.equal(Object.hasOwn(result, 'grove_settings'), false)
    assert.equal(result.flavor, 'claude_code')
    assert.equal(payloads.at(-1).operation, 'exchange_code')
    assert.equal(payloads.at(-1).code, 'legacy-code')
    assert.equal(payloads.at(-1).state, 'legacy-provider-state')
    assert.equal(payloads.at(-1).redirect_uri, OAUTH_FLAVORS.claude_code.redirectUri)
    assert.equal(payloads.at(-1).proxy_url, '')
  }
  assert.equal(payloads.length, 5)
  process.env.VM2API_SKIP_GROVE_SETTINGS = '1'
  const generated = generateAuthUrl({ vmId: 'vm-legacy', proxyUrl: '' })
  const result = await exchangeAuthCode({
    sessionId: generated.session_id,
    code: 'legacy-code',
    vmId: 'vm-legacy',
    skipGroveSettings: false,
  })
  assert.equal(payloads.length, 6)
  assert.equal(Object.hasOwn(result, 'grove_settings'), false)
})

test('the server flag does not reroute sessionKey imports away from cookie-auth', async (t) => {
  isolateOAuthEnv(t)
  process.env.VM2API_SKIP_GROVE_SETTINGS = 'true'
  const payloads = mockLegacyService(t)
  const result = await sessionKeyToOAuth('sk-ant-sid01-legacy-fixture', { proxyUrl: '' })
  assert.equal(payloads.length, 1)
  assert.equal(payloads[0].operation, 'session_key')
  assert.equal(result.email, 'legacy@example.test')
  assert.equal(Object.hasOwn(result, 'grove_settings'), false)
})

test('strict exchange rejects expired sessions, wrong VM/setup state and missing code before HTTP', async (t) => {
  isolateOAuthEnv(t)
  for (const scenario of ['expired', 'vm', 'state', 'code']) {
    await t.test(scenario, async () => {
      const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '', flavor: 'setup_token' })
      const session = peekAuthUrlSession(generated.session_id)
      if (scenario === 'expired') session.createdAt -= 31 * 60 * 1000
      let calls = 0
      await assert.rejects(
        exchangeAuthCode({
          sessionId: generated.session_id,
          code: scenario === 'code' ? '' : `strict-code#${scenario === 'state' ? 'wrong-state' : session.state}`,
          vmId: scenario === 'vm' ? 'vm-other' : 'vm-strict',
          skipGroveSettings: true,
          fetchImpl: async () => {
            calls++
          },
        }),
        {
          code: {
            expired: 'session_expired',
            vm: 'session_vm_mismatch',
            state: 'state_mismatch',
            code: 'code_required',
          }[scenario],
        },
      )
      assert.equal(calls, 0)
      assert.notEqual(session.exchanging, true)
    })
  }
})

test('concurrent exchange on one session returns 409 while the first exchange alone consumes it', {
  timeout: 2000,
}, async (t) => {
  isolateOAuthEnv(t)
  const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '' })
  const session = peekAuthUrlSession(generated.session_id)
  let release
  let entered
  const started = new Promise((resolve) => {
    entered = resolve
  })
  let calls = 0
  const input = {
    sessionId: generated.session_id,
    code: 'strict-code',
    vmId: 'vm-strict',
    skipGroveSettings: true,
    fetchImpl: async () => {
      calls++
      if (calls === 1) {
        entered()
        return new Promise((resolve) => {
          release = resolve
        })
      }
      return oauthResponse(200, exchangedIdentity)
    },
  }
  const first = exchangeAuthCode(input)
  t.after(() => release?.(oauthResponse(200, exchangedToken)))
  await Promise.race([started, first])
  assert.equal(session.exchanging, true)
  await assert.rejects(exchangeAuthCode(input), { code: 'exchange_in_progress', httpStatus: 409 })
  assert.equal(calls, 1)
  release(oauthResponse(200, exchangedToken))
  assert.equal((await first).access_token, exchangedToken.access_token)
  assert.equal(calls, 2)
  assert.equal(session.exchanging, false)
  assert.equal(peekAuthUrlSession(generated.session_id), null)
})

test('a successful token followed by failed bootstrap consumes the session and clears its original busy flag', async (t) => {
  isolateOAuthEnv(t)
  const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '' })
  const session = peekAuthUrlSession(generated.session_id)
  let calls = 0
  const input = {
    sessionId: generated.session_id,
    code: 'strict-code',
    vmId: 'vm-strict',
    skipGroveSettings: true,
    fetchImpl: async (url) => {
      calls++
      if (url === CLAUDE_CLI_BOOTSTRAP_URL) {
        assert.equal(peekAuthUrlSession(generated.session_id), null)
        return oauthResponse(403, { error: { message: 'sk-ant-oat01-LEAK password=secret strict-code' } })
      }
      return oauthResponse(200, exchangedToken)
    },
  }
  await assert.rejects(exchangeAuthCode(input), (error) => {
    assert.equal(error.httpStatus, 502)
    assert.equal(error.message.includes('sk-ant-oat01-LEAK'), false)
    assert.equal(error.message.includes('password='), false)
    assert.equal(error.message.includes('strict-code'), false)
    return true
  })
  assert.equal(calls, 2)
  assert.equal(session.exchanging, false)
  assert.equal(peekAuthUrlSession(generated.session_id), null)
  await assert.rejects(exchangeAuthCode(input), { code: 'session_expired' })
  assert.equal(calls, 2)
})

test('token rejection clears the busy flag without automatically replaying or consuming the session', async (t) => {
  isolateOAuthEnv(t)
  const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '' })
  const session = peekAuthUrlSession(generated.session_id)
  let calls = 0
  await assert.rejects(
    exchangeAuthCode({
      sessionId: generated.session_id,
      code: 'strict-code',
      vmId: 'vm-strict',
      skipGroveSettings: true,
      fetchImpl: async () => {
        calls++
        return oauthResponse(400, { error: 'invalid_grant' })
      },
    }),
    { code: 'invalid_grant', httpStatus: 400 },
  )
  assert.equal(calls, 1)
  assert.equal(peekAuthUrlSession(generated.session_id), session)
  assert.equal(session.exchanging, false)
})

test('token URL candidates remain session-defined and the caller cannot inject token endpoints', async (t) => {
  isolateOAuthEnv(t)
  const generated = generateAuthUrl({ vmId: 'vm-strict', proxyUrl: '', flavor: 'claude_code' })
  const seen = []
  const result = await exchangeAuthCode({
    sessionId: generated.session_id,
    code: 'strict-code',
    vmId: 'vm-strict',
    skipGroveSettings: true,
    tokenUrls: ['https://evil.test/v1/oauth/token'],
    fetchImpl: async (url) => {
      seen.push(url)
      if (url === CLAUDE_CLI_BOOTSTRAP_URL) return oauthResponse(200, exchangedIdentity)
      if (url === OAUTH_FLAVORS.claude_code.tokenUrls[2]) return oauthResponse(200, exchangedToken)
      return oauthResponse(404, {})
    },
  })
  assert.equal(result.access_token, exchangedToken.access_token)
  assert.deepEqual(seen, [...OAUTH_FLAVORS.claude_code.tokenUrls, CLAUDE_CLI_BOOTSTRAP_URL])
})
