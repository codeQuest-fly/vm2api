import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { PassThrough } from 'node:stream'
import { Response } from 'node-fetch'
import { exchangeAuthorizationCodeWithoutGrove } from '../../src/lib/oauth/oauth-code-exchange.mjs'
import {
  CLIENT_ID,
  TOKEN_URL,
  REDIRECT_URI,
  TOKEN_UA,
  OFFICIAL_CLI_HEADERS,
  FULL_OAUTH_SCOPE,
} from '../../src/lib/oauth/oauth-contract.mjs'
import { CLAUDE_CLI_BOOTSTRAP_URL, bootstrapRequestHeaders } from '../../src/lib/oauth/oauth-identity.mjs'

const token = {
  access_token: 'sk-ant-oat01-MOCK-ACCESS',
  refresh_token: 'sk-ant-ort01-MOCK-REFRESH',
  token_type: 'Bearer',
  expires_in: 28800,
  scope: FULL_OAUTH_SCOPE,
}
const bootstrap = {
  oauth_account: {
    account_email: 'exchange@example.test',
    account_uuid: 'acct-exchange',
    organization_uuid: 'org-exchange',
  },
  organization: { organization_type: 'claude_max' },
}
const tokenUrls = [
  TOKEN_URL,
  'https://api.anthropic.com/v1/oauth/token',
  'https://console.anthropic.com/v1/oauth/token',
]
const secrets = [
  token.access_token,
  token.refresh_token,
  'pasted-code-secret',
  'verifier-secret',
  'proxy-user-secret',
  'proxy-password-secret',
]

function options(extra = {}) {
  return {
    code: 'pasted-code-secret',
    codeVerifier: 'verifier-secret',
    state: 'provider-state',
    redirectUri: REDIRECT_URI,
    tokenUrls,
    proxyUrl: '',
    ...extra,
  }
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function safeError(error, httpStatus, code = null) {
  assert.equal(error.httpStatus, httpStatus)
  assert.equal(typeof error.code, 'string')
  if (code) assert.equal(error.code, code)
  const serialized = `${error.message}\n${error.stack}\n${JSON.stringify(error)}`
  for (const secret of secrets) assert.equal(serialized.includes(secret), false, 'error must not expose secrets')
  for (const key of ['body', 'headers', 'response', 'cause', 'access_token', 'code_verifier', 'proxyUrl']) {
    assert.equal(Object.hasOwn(error, key), false)
  }
  return true
}

function successfulFetch(seen = []) {
  return async (url, init) => {
    seen.push({ url, init })
    if (url === CLAUDE_CLI_BOOTSTRAP_URL) return jsonResponse(200, bootstrap)
    return jsonResponse(200, token)
  }
}

test('strict exchange requests only token and bootstrap, preserving the OAuth contract and real credentials', async () => {
  const seen = []
  let consumed = 0
  const before = Math.floor(Date.now() / 1000)
  const result = await exchangeAuthorizationCodeWithoutGrove(
    options({
      onTokenExchanged(...args) {
        assert.deepEqual(args, [])
        consumed++
      },
      fetchImpl: async (url, init) => {
        assert.equal(consumed, seen.length ? 1 : 0)
        seen.push({ url, init })
        return jsonResponse(200, seen.length === 1 ? token : bootstrap)
      },
    }),
  )
  assert.equal(consumed, 1)
  assert.equal(seen.length, 2)
  assert.equal(seen.filter(({ init }) => init.method === 'PATCH').length, 0)
  assert.equal(seen.filter(({ url }) => url.includes('/settings')).length, 0)
  assert.equal(seen[0].url, TOKEN_URL)
  assert.equal(seen[0].init.method, 'POST')
  assert.deepEqual(JSON.parse(seen[0].init.body), {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code: 'pasted-code-secret',
    code_verifier: 'verifier-secret',
    redirect_uri: REDIRECT_URI,
    state: 'provider-state',
  })
  assert.deepEqual(seen[0].init.headers, {
    ...OFFICIAL_CLI_HEADERS,
    'user-agent': TOKEN_UA,
    'content-type': 'application/json',
    accept: 'application/json',
  })
  assert.equal(seen[1].url, CLAUDE_CLI_BOOTSTRAP_URL)
  assert.equal(seen[1].init.method, 'GET')
  assert.equal(seen[1].init.headers['x-app'], 'cli')
  assert.deepEqual(seen[1].init.headers, {
    ...OFFICIAL_CLI_HEADERS,
    ...bootstrapRequestHeaders(token.access_token),
  })
  for (const { init } of seen) {
    assert.equal(init.redirect, 'error')
    assert.ok(init.signal instanceof AbortSignal)
    assert.equal(init.agent, undefined)
    assert.equal(init.rejectUnauthorized, undefined)
    assert.ok(init.size > 0 && init.size <= 65536)
  }
  for (const key of ['access_token', 'refresh_token', 'token_type', 'scope', 'expires_in']) {
    assert.equal(result[key], token[key])
  }
  assert.ok(result.expires_at >= before + token.expires_in)
  assert.ok(result.expires_at <= Math.floor(Date.now() / 1000) + token.expires_in)
  assert.equal(result.email, 'exchange@example.test')
  assert.equal(result.email_address, 'exchange@example.test')
  assert.equal(result.account_uuid, 'acct-exchange')
  assert.equal(result.org_uuid, 'org-exchange')
  assert.equal(result.subscription_type, 'max')
  assert.deepEqual(result.grove_settings, { status: 'skipped', reason: 'disabled_by_operator' })
  assert.equal(Object.hasOwn(result, 'privacy_updated'), false)
})

test('empty or omitted state is absent from the token JSON and default URL/callback use the shared contract', async (t) => {
  for (const state of ['', null, undefined]) {
    await t.test(String(state), async () => {
      const seen = []
      await exchangeAuthorizationCodeWithoutGrove(
        options({
          state,
          tokenUrls: undefined,
          redirectUri: undefined,
          fetchImpl: successfulFetch(seen),
        }),
      )
      const body = JSON.parse(seen[0].init.body)
      assert.equal(Object.hasOwn(body, 'state'), false)
      assert.equal(body.redirect_uri, REDIRECT_URI)
      assert.equal(seen[0].url, TOKEN_URL)
    })
  }
})

test('404 and 405 alone permit fallback to the remaining trusted token endpoints', async (t) => {
  for (const statuses of [
    [404, 405],
    [405, 404],
  ]) {
    await t.test(statuses.join('-'), async () => {
      const seen = []
      let consumed = 0
      const result = await exchangeAuthorizationCodeWithoutGrove(
        options({
          onTokenExchanged: () => {
            consumed++
          },
          fetchImpl: async (url, init) => {
            seen.push({ url, init })
            if (url === CLAUDE_CLI_BOOTSTRAP_URL) return jsonResponse(200, bootstrap)
            const status = statuses[seen.length - 1]
            return status ? new Response('not found', { status }) : jsonResponse(200, token)
          },
        }),
      )
      assert.equal(result.access_token, token.access_token)
      assert.deepEqual(
        seen.map(({ url }) => url),
        [...tokenUrls, CLAUDE_CLI_BOOTSTRAP_URL],
      )
      assert.equal(seen.filter(({ init }) => init.method === 'POST').length, 3)
      assert.equal(consumed, 1)
    })
  }
})

test('exhausted or duplicated 404/405 candidates fail without another request', async (t) => {
  for (const urls of [[TOKEN_URL], [TOKEN_URL, TOKEN_URL], tokenUrls]) {
    await t.test(urls.join(','), async () => {
      let calls = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            tokenUrls: urls,
            fetchImpl: async () => {
              calls++
              return jsonResponse(404, { error: 'not_found' })
            },
          }),
        ),
        (error) => safeError(error, 502),
      )
      assert.equal(calls, new Set(urls).size)
    })
  }
})

test('untrusted URLs and unusable token URL lists are rejected before any request', async (t) => {
  for (const urls of [
    [],
    null,
    TOKEN_URL,
    ['http://platform.claude.com/v1/oauth/token'],
    ['https://platform.claude.com.evil.test/v1/oauth/token'],
    ['https://proxy-user-secret:proxy-password-secret@platform.claude.com/v1/oauth/token'],
    ['https://platform.claude.com:444/v1/oauth/token'],
    ['https://platform.claude.com/v1/oauth/token?redirect=evil'],
    [TOKEN_URL, 'https://evil.test/v1/oauth/token'],
  ]) {
    await t.test(JSON.stringify(urls), async () => {
      let calls = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            tokenUrls: urls,
            fetchImpl: async () => {
              calls++
            },
          }),
        ),
        (error) => safeError(error, 400),
      )
      assert.equal(calls, 0)
    })
  }
})

test('invalid grant and other token HTTP rejections never replay the code or expose the body', async (t) => {
  for (const [status, errorBody, httpStatus] of [
    [400, 'invalid_grant', 400],
    [400, { type: 'invalid_grant' }, 400],
    [400, { type: 'invalid_request_error' }, 400],
    [401, { type: 'authentication_error' }, 502],
    [403, { type: 'permission_error' }, 502],
    [429, { type: 'rate_limit_error' }, 502],
    [500, { type: 'api_error' }, 502],
    [503, { type: 'overloaded_error' }, 502],
  ]) {
    await t.test(`${status}: ${JSON.stringify(errorBody)}`, async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              return jsonResponse(status, {
                error: errorBody,
                error_description: secrets.join(' '),
                request_id: secrets.join(' '),
                access_token: token.access_token,
              })
            },
          }),
        ),
        (error) => {
          safeError(error, httpStatus)
          if (errorBody === 'invalid_grant' || errorBody.type === 'invalid_grant') {
            assert.equal(error.code, 'invalid_grant')
          }
          return true
        },
      )
      assert.equal(calls, 1)
      assert.equal(consumed, 0)
    })
  }
})

test('network, redirect and SOCKS authentication errors fail closed without fallback or secret leakage', async (t) => {
  for (const [message, name, expectedStatus, expectedCode] of [
    [`connection reset ${secrets.join(' ')}`, 'Error', 502, null],
    [`redirect not allowed ${secrets.join(' ')}`, 'FetchError', 502, null],
    [`Socks5 Authentication failed ${secrets.join(' ')}`, 'Error', 400, 'proxy_auth_rejected'],
    [`User was rejected by the SOCKS5 server ${secrets.join(' ')}`, 'Error', 400, 'proxy_auth_rejected'],
  ]) {
    await t.test(name + ':' + expectedStatus + ':' + (expectedCode || 'network'), async () => {
      const seen = []
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            proxyUrl: 'socks5h://proxy-user-secret:proxy-password-secret@127.0.0.1:1080',
            fetchImpl: async (url, init) => {
              seen.push({ url, init })
              const error = new Error(message)
              error.name = name
              throw error
            },
          }),
        ),
        (error) => safeError(error, expectedStatus, expectedCode),
      )
      assert.equal(seen.length, 1)
      assert.ok(seen[0].init.agent)
      assert.notEqual(seen[0].init.agent.options?.rejectUnauthorized, false)
    })
  }
})

test('HTTP proxy authentication refusal maps to proxy_auth_rejected rather than upstream user authentication', async () => {
  let calls = 0
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        proxyUrl: 'http://proxy-user-secret:proxy-password-secret@127.0.0.1:1080',
        fetchImpl: async () => {
          calls++
          return jsonResponse(407, { error: { message: secrets.join(' ') } })
        },
      }),
    ),
    (error) => safeError(error, 400, 'proxy_auth_rejected'),
  )
  assert.equal(calls, 1)
})

test('null, undefined and malformed proxies are refused even with an injected fetch', async (t) => {
  for (const proxyUrl of [null, undefined, ' ', 'not-a-proxy', 'ftp://proxy-user-secret:proxy-password-secret@host']) {
    await t.test(String(proxyUrl), async () => {
      let calls = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            proxyUrl,
            fetchImpl: async () => {
              calls++
            },
          }),
        ),
        (error) => safeError(error, 400),
      )
      assert.equal(calls, 0)
    })
  }
})

test('real node-fetch and SOCKS factory stop after localhost proxy authentication refusal', {
  timeout: 3000,
}, async (t) => {
  const sockets = new Set()
  let connections = 0
  let authenticationAttempts = 0
  const proxy = net.createServer((socket) => {
    sockets.add(socket)
    connections++
    socket.on('error', () => {})
    socket.on('close', () => sockets.delete(socket))
    let pending = Buffer.alloc(0)
    let greeted = false
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk])
      if (!greeted) {
        if (pending.length < 2 || pending.length < 2 + pending[1]) return
        pending = pending.subarray(2 + pending[1])
        greeted = true
        socket.write(Buffer.from([5, 2]))
      }
      if (pending.length < 2 || pending.length < 3 + pending[1]) return
      const passwordLength = pending[2 + pending[1]]
      if (pending.length < 3 + pending[1] + passwordLength) return
      authenticationAttempts++
      pending = Buffer.alloc(0)
      socket.end(Buffer.from([1, 1]))
    })
  })
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
  t.after(async () => {
    for (const socket of sockets) socket.destroy()
    await new Promise((resolve) => proxy.close(resolve))
  })
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        proxyUrl: `socks5h://proxy-user-secret:proxy-password-secret@127.0.0.1:${proxy.address().port}`,
        timeoutMs: 1000,
      }),
    ),
    (error) => safeError(error, 400, 'proxy_auth_rejected'),
  )
  assert.equal(connections, 1)
  assert.equal(authenticationAttempts, 1)
})

test('the request deadline includes fetch even when an injected transport ignores abort', {
  timeout: 2000,
}, async () => {
  let calls = 0
  let signal
  const started = Date.now()
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        timeoutMs: 25,
        fetchImpl: (_url, init) => {
          calls++
          signal = init.signal
          return new Promise(() => {})
        },
      }),
    ),
    (error) => safeError(error, 504),
  )
  assert.equal(calls, 1)
  assert.equal(signal.aborted, true)
  assert.ok(Date.now() - started < 1000)
})

test('the token deadline remains active after headers until the complete body is read', { timeout: 2000 }, async () => {
  const body = new PassThrough()
  body.write('{"access_token":')
  let calls = 0
  let consumed = 0
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        timeoutMs: 25,
        onTokenExchanged: () => {
          consumed++
        },
        fetchImpl: async () => {
          calls++
          return new Response(body, { status: 200 })
        },
      }),
    ),
    (error) => safeError(error, 504),
  )
  assert.equal(calls, 1)
  assert.equal(consumed, 0)
  assert.equal(body.destroyed, true)
})

test('internal timeouts cap at 30000 ms while preserving the default and short test deadlines', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  for (const [timeoutMs, expectedMs] of [
    [undefined, 15000],
    [25, 25],
    [60000, 30000],
    [2147483647, 30000],
  ]) {
    await t.test(String(timeoutMs), async (caseT) => {
      let signal
      let calls = 0
      const operation = exchangeAuthorizationCodeWithoutGrove(
        options({
          timeoutMs,
          fetchImpl: (_url, init) => {
            calls++
            signal = init.signal
            return new Promise(() => {})
          },
        }),
      )
      const rejected = assert.rejects(operation, (error) => safeError(error, 504))
      caseT.after(async () => {
        t.mock.timers.runAll()
        await rejected
      })
      t.mock.timers.tick(expectedMs - 1)
      assert.equal(signal.aborted, false)
      t.mock.timers.tick(1)
      assert.equal(signal.aborted, true)
      await rejected
      assert.equal(calls, 1)
    })
  }
})

test('each request receives its own deadline rather than a shared token-plus-bootstrap timer', {
  timeout: 2000,
}, async () => {
  let calls = 0
  const result = await exchangeAuthorizationCodeWithoutGrove(
    options({
      timeoutMs: 200,
      fetchImpl: async () => {
        calls++
        await new Promise((resolve) => setTimeout(resolve, 130))
        return jsonResponse(200, calls === 1 ? token : bootstrap)
      },
    }),
  )
  assert.equal(calls, 2)
  assert.equal(result.access_token, token.access_token)
})

test('responses larger than 64 KiB fail both before and after token consumption', async (t) => {
  for (const stage of ['token', 'bootstrap']) {
    await t.test(stage, async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              if (stage === 'bootstrap' && calls === 1) return jsonResponse(200, token)
              return new Response(' '.repeat(65537), { status: 200 })
            },
          }),
        ),
        (error) => safeError(error, 502),
      )
      assert.equal(calls, stage === 'token' ? 1 : 2)
      assert.equal(consumed, stage === 'token' ? 0 : 1)
    })
  }
})

test('token JSON and access/expiry validation fail before bootstrap and do not claim token consumption', async (t) => {
  const cases = [
    ['invalid JSON', '{'],
    ['null', 'null'],
    ['array', '[]'],
    ['missing access', JSON.stringify({ expires_in: 3600 })],
    ['blank access', JSON.stringify({ ...token, access_token: '  ' })],
    ['object access', JSON.stringify({ ...token, access_token: {} })],
    ...[undefined, 0, -1, true, 'not-a-duration', 1e20].map((expires_in) => [
      `invalid expiry ${String(expires_in)}`,
      JSON.stringify({ ...token, expires_in }),
    ]),
    ['expired absolute expiry', JSON.stringify({ ...token, expires_in: undefined, expires_at: 1 })],
  ]
  for (const [name, text] of cases) {
    await t.test(name, async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              return new Response(text, { status: 200 })
            },
          }),
        ),
        (error) => safeError(error, 502),
      )
      assert.equal(calls, 1)
      assert.equal(consumed, 0)
    })
  }
})

test('unsupported token types fail before token consumption and bootstrap', async (t) => {
  for (const [name, tokenType] of [
    ['MAC', 'MAC'],
    ['arbitrary type', 'Basic'],
    ['object', {}],
    ['numeric', 42],
    ['null', null],
    ['boolean', true],
    ['whitespace', 'bearer '],
  ]) {
    await t.test(name, async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async (url) => {
              calls++
              return jsonResponse(
                200,
                url === CLAUDE_CLI_BOOTSTRAP_URL ? bootstrap : { ...token, token_type: tokenType },
              )
            },
          }),
        ),
        (error) => safeError(error, 502, 'token_response_invalid'),
      )
      assert.equal(calls, 1)
      assert.equal(consumed, 0)
    })
  }
})

test('missing, empty and case-insensitive Bearer token types remain compatible', async (t) => {
  for (const tokenType of [undefined, '', 'bearer', 'bEaReR']) {
    await t.test(String(tokenType), async () => {
      let calls = 0
      let consumed = 0
      const result = await exchangeAuthorizationCodeWithoutGrove(
        options({
          onTokenExchanged: () => {
            consumed++
          },
          fetchImpl: async (url) => {
            calls++
            return jsonResponse(200, url === CLAUDE_CLI_BOOTSTRAP_URL ? bootstrap : { ...token, token_type: tokenType })
          },
        }),
      )
      assert.equal(result.token_type, tokenType || 'Bearer')
      assert.equal(result.access_token, token.access_token)
      assert.equal(calls, 2)
      assert.equal(consumed, 1)
    })
  }
})

test('usable absolute expiry is preserved in seconds, including millisecond input', async (t) => {
  for (const multiplier of [1, 1000]) {
    await t.test(String(multiplier), async () => {
      const expiresAt = Math.floor(Date.now() / 1000) + 3600
      const result = await exchangeAuthorizationCodeWithoutGrove(
        options({
          fetchImpl: async (url) =>
            jsonResponse(
              200,
              url === CLAUDE_CLI_BOOTSTRAP_URL
                ? bootstrap
                : {
                    ...token,
                    expires_in: undefined,
                    expires_at: expiresAt * multiplier,
                  },
            ),
        }),
      )
      assert.equal(result.expires_at, expiresAt)
      assert.ok(result.expires_in > 0 && result.expires_in <= 3600)
    })
  }
})

test('bootstrap HTTP rejection, invalid JSON and incomplete identity are strict failures even if token identity is complete', async (t) => {
  for (const [name, status, text] of [
    ['unauthorized', 401, '{}'],
    ['forbidden', 403, '{}'],
    ['server error', 500, '{}'],
    ['unavailable', 503, '{}'],
    ['redirect', 302, '{}'],
    ['invalid JSON', 200, '{'],
    ['null JSON', 200, 'null'],
    ['array JSON', 200, '[]'],
    ['empty identity', 200, '{}'],
    ['email only', 200, JSON.stringify({ email: 'exchange@example.test' })],
    ['missing org', 200, JSON.stringify({ email: 'exchange@example.test', account_uuid: 'acct-exchange' })],
    ['invalid identity', 200, JSON.stringify({ email: {}, account_uuid: {}, org_uuid: {} })],
  ]) {
    await t.test(name, async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              if (calls === 1)
                return jsonResponse(200, {
                  ...token,
                  email: 'already-complete@example.test',
                  account_uuid: 'already-complete',
                  org_uuid: 'already-complete',
                })
              return new Response(text, { status })
            },
          }),
        ),
        (error) => safeError(error, 502),
      )
      assert.equal(calls, 2)
      assert.equal(consumed, 1)
    })
  }
})

test('bootstrap fetch/body timeouts and network errors never return a credential or replay the token request', {
  timeout: 2000,
}, async (t) => {
  for (const stage of ['fetch', 'body', 'network']) {
    await t.test(stage, async () => {
      const body = new PassThrough()
      body.write('{')
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            timeoutMs: 25,
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              if (calls === 1) return jsonResponse(200, token)
              if (stage === 'fetch') return new Promise(() => {})
              if (stage === 'body') return new Response(body, { status: 200 })
              throw new Error(secrets.join(' '))
            },
          }),
        ),
        (error) => safeError(error, stage === 'network' ? 502 : 504),
      )
      assert.equal(calls, 2)
      assert.equal(consumed, 1)
      body.destroy()
    })
  }
})

test('token consumption callback errors are filtered and cannot produce a success', async () => {
  let calls = 0
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        onTokenExchanged() {
          throw new Error(secrets.join(' '))
        },
        fetchImpl: async () => {
          calls++
          return jsonResponse(200, token)
        },
      }),
    ),
    (error) => safeError(error, 502),
  )
  assert.equal(calls, 1)
})

test('transport-reported timeouts map to 504 without replay or secret disclosure', async (t) => {
  for (const fields of [
    { code: 'ETIMEDOUT' },
    { name: 'AbortError' },
    { type: 'request-timeout' },
    { type: 'body-timeout' },
    { message: `Proxy connection timed out ${secrets.join(' ')}` },
  ]) {
    await t.test(fields.code || fields.name || fields.type || 'SOCKS timeout', async () => {
      let calls = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            fetchImpl: async () => {
              calls++
              throw Object.assign(new Error(secrets.join(' ')), fields)
            },
          }),
        ),
        (error) => safeError(error, 504),
      )
      assert.equal(calls, 1)
    })
  }
})

test('bootstrap identity fields must be actual strings and malformed identity processing is filtered', async (t) => {
  for (const identity of [
    { email: 'exchange@example.test', account_uuid: 123, org_uuid: 'org-exchange' },
    { email: 'exchange@example.test', account_uuid: true, org_uuid: 'org-exchange' },
    { email: ['exchange@example.test'], account_uuid: ['acct-exchange'], org_uuid: ['org-exchange'] },
    { email: { toString: null }, account_uuid: 'acct-exchange', org_uuid: 'org-exchange' },
  ]) {
    await t.test(JSON.stringify(identity), async () => {
      let calls = 0
      let consumed = 0
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            onTokenExchanged: () => {
              consumed++
            },
            fetchImpl: async () => {
              calls++
              return jsonResponse(200, calls === 1 ? token : identity)
            },
          }),
        ),
        (error) => safeError(error, 502, 'bootstrap_identity_invalid'),
      )
      assert.equal(calls, 2)
      assert.equal(consumed, 1)
    })
  }
})

test('oversized streamed responses stop reading immediately and destroy the body', { timeout: 2000 }, async () => {
  const body = new PassThrough()
  body.write(' '.repeat(65537))
  let calls = 0
  await assert.rejects(
    exchangeAuthorizationCodeWithoutGrove(
      options({
        timeoutMs: 1000,
        fetchImpl: async () => {
          calls++
          return new Response(body, { status: 200 })
        },
      }),
    ),
    (error) => safeError(error, 502, 'oauth_response_too_large'),
  )
  assert.equal(calls, 1)
  assert.equal(body.destroyed, true)
})

test('late fetch/body completion cannot beat a deadline whose timer was delayed by the event loop', async (t) => {
  for (const stage of ['fetch', 'body']) {
    await t.test(stage, async () => {
      let calls = 0
      const delay = () => {
        const end = performance.now() + 30
        while (performance.now() < end) {}
      }
      await assert.rejects(
        exchangeAuthorizationCodeWithoutGrove(
          options({
            timeoutMs: 10,
            fetchImpl: async () => {
              calls++
              if (stage === 'fetch') delay()
              return {
                status: 200,
                text: async () => {
                  if (stage === 'body') delay()
                  return JSON.stringify(calls === 1 ? token : bootstrap)
                },
              }
            },
          }),
        ),
        (error) => safeError(error, 504),
      )
      assert.equal(calls, 1)
    })
  }
})
