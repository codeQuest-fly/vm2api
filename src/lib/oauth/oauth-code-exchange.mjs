import fetch from 'node-fetch'
import { createProxyAgent } from '../vm/proxy-agent.mjs'
import { CLIENT_ID, TOKEN_URL, REDIRECT_URI, TOKEN_UA, OFFICIAL_CLI_HEADERS } from './oauth-contract.mjs'
import {
  CLAUDE_CLI_BOOTSTRAP_URL,
  bootstrapRequestHeaders,
  flattenOauthIdentity,
  oauthIdentityComplete,
  applyOauthIdentity,
} from './oauth-identity.mjs'

const TRUSTED_TOKEN_URLS = new Set([
  TOKEN_URL,
  'https://api.anthropic.com/v1/oauth/token',
  'https://console.anthropic.com/v1/oauth/token',
])
const MAX_RESPONSE_BYTES = 64 * 1024
const MAX_TOKEN_LIFETIME_SECONDS = 366 * 24 * 60 * 60
const IDENTITY_TEXT_FIELDS = new Set([
  'email',
  'email_address',
  'emailAddress',
  'account_email',
  'account_uuid',
  'accountUuid',
  'uuid',
  'org_uuid',
  'orgUuid',
  'organization_uuid',
])

class ExchangeError extends Error {
  constructor(code, message, httpStatus, upstreamStatus = null) {
    super(message)
    this.code = code
    this.httpStatus = httpStatus
    if (upstreamStatus != null) this.upstreamStatus = upstreamStatus
  }
}

function proxyAuthRejected(error) {
  return (
    error?.code === 'proxy_auth_rejected' ||
    /proxy_auth_rejected|socks5 authentication failed|user was rejected by the socks5 server|socks5.*no accepted authentication type|proxy authentication required/i.test(
      String(error?.message || ''),
    )
  )
}

function closeResponse(response) {
  try {
    response?.body?.destroy?.()
    response?.body?.cancel?.().catch(() => {})
  } catch {}
}

async function readLimitedBody(response) {
  if (response.body && typeof response.body[Symbol.asyncIterator] === 'function') {
    const chunks = []
    let size = 0
    for await (const chunk of response.body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      size += buffer.length
      if (size > MAX_RESPONSE_BYTES) {
        throw new ExchangeError('oauth_response_too_large', 'OAuth response exceeded the size limit', 502)
      }
      chunks.push(buffer)
    }
    return Buffer.concat(chunks, size).toString('utf8')
  }
  let text
  if (typeof response.text === 'function') text = await response.text()
  else if (typeof response.json === 'function') text = JSON.stringify(await response.json())
  if (typeof text !== 'string') {
    throw new ExchangeError('oauth_response_invalid', 'OAuth endpoint returned an invalid response', 502)
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    throw new ExchangeError('oauth_response_too_large', 'OAuth response exceeded the size limit', 502)
  }
  return text
}

async function requestJson(url, init, { agent, fetchFn, timeoutMs, stage }) {
  const controller = new AbortController()
  const deadlineAt = performance.now() + timeoutMs
  let response
  let timer
  let timedOut = false
  const timeoutError = () => new ExchangeError(`${stage}_timeout`, `OAuth ${stage} request timed out`, 504)
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true
      controller.abort()
      closeResponse(response)
      reject(timeoutError())
    }, timeoutMs)
  })
  try {
    const operation = (async () => {
      response = await fetchFn(url, {
        ...init,
        agent,
        signal: controller.signal,
        redirect: 'error',
        size: MAX_RESPONSE_BYTES,
      })
      if (controller.signal.aborted || performance.now() >= deadlineAt) {
        closeResponse(response)
        throw timeoutError()
      }
      const status = response?.status
      if (!Number.isInteger(status) || status < 200 || status > 599) {
        throw new ExchangeError(
          `${stage}_response_invalid`,
          `OAuth ${stage} endpoint returned an invalid response`,
          502,
        )
      }
      const text = await readLimitedBody(response)
      let body = null
      try {
        body = JSON.parse(text)
      } catch {
        if (status < 300) {
          throw new ExchangeError(`${stage}_response_invalid`, `OAuth ${stage} endpoint returned invalid JSON`, 502)
        }
      }
      if (status < 300 && (!body || typeof body !== 'object' || Array.isArray(body))) {
        throw new ExchangeError(`${stage}_response_invalid`, `OAuth ${stage} endpoint returned invalid JSON`, 502)
      }
      if (performance.now() >= deadlineAt) throw timeoutError()
      return { status, body }
    })()
    return await Promise.race([operation, deadline])
  } catch (error) {
    controller.abort()
    closeResponse(response)
    if (timedOut || performance.now() >= deadlineAt) throw timeoutError()
    if (error instanceof ExchangeError) throw error
    if (proxyAuthRejected(error)) {
      throw new ExchangeError('proxy_auth_rejected', 'Slot proxy rejected authentication', 400)
    }
    if (
      error?.code === 'ETIMEDOUT' ||
      error?.code === 'ESOCKETTIMEDOUT' ||
      error?.name === 'AbortError' ||
      error?.type === 'request-timeout' ||
      error?.type === 'body-timeout' ||
      /\bProxy connection timed out\b/i.test(String(error?.message || ''))
    )
      throw timeoutError()
    throw new ExchangeError(`${stage}_network_failed`, `OAuth ${stage} request failed`, 502)
  } finally {
    clearTimeout(timer)
  }
}

function httpFailure(stage, status, body) {
  if (status === 407) {
    return new ExchangeError('proxy_auth_rejected', 'Slot proxy rejected authentication', 400, status)
  }
  if (
    stage === 'token' &&
    status === 400 &&
    (body?.error === 'invalid_grant' || body?.error?.type === 'invalid_grant' || body?.error?.code === 'invalid_grant')
  ) {
    return new ExchangeError('invalid_grant', 'Authorization code was rejected or has already been used', 400, status)
  }
  return new ExchangeError(
    `${stage}_failed`,
    `OAuth ${stage} endpoint rejected the request (HTTP ${status})`,
    stage === 'token' && status === 400 ? 400 : 502,
    status,
  )
}

function numericValue(value) {
  return typeof value === 'number' || (typeof value === 'string' && value.trim()) ? Number(value) : NaN
}

function normalizeToken(body) {
  const invalid = () =>
    new ExchangeError('token_response_invalid', 'OAuth token endpoint returned invalid credentials', 502)
  if (typeof body.access_token !== 'string' || !body.access_token.trim() || /\s/.test(body.access_token))
    throw invalid()
  for (const key of ['refresh_token', 'scope']) {
    if (body[key] != null && typeof body[key] !== 'string') throw invalid()
  }
  if (
    body.token_type !== undefined &&
    (typeof body.token_type !== 'string' || (body.token_type !== '' && body.token_type.toLowerCase() !== 'bearer'))
  )
    throw invalid()
  const now = Math.floor(Date.now() / 1000)
  const hasDuration = body.expires_in != null
  const duration = numericValue(body.expires_in)
  if (hasDuration && (!Number.isFinite(duration) || duration <= 0 || duration > MAX_TOKEN_LIFETIME_SECONDS))
    throw invalid()
  const rawExpiry = body.expires_at ?? body.expiresAt
  const hasExpiry = rawExpiry != null
  const expiry = numericValue(rawExpiry)
  const expiresAt = hasExpiry
    ? Math.floor(expiry > 10_000_000_000 ? expiry / 1000 : expiry)
    : Math.floor(now + duration)
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > MAX_TOKEN_LIFETIME_SECONDS)
    throw invalid()
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token || '',
    token_type: body.token_type || 'Bearer',
    scope: body.scope || '',
    expires_in: hasDuration ? duration : expiresAt - now,
    expires_at: expiresAt,
  }
}

function strictBootstrapIdentity(body) {
  const invalid = () =>
    new ExchangeError(
      'bootstrap_identity_invalid',
      'OAuth bootstrap returned an incomplete or invalid account identity',
      502,
    )
  try {
    for (const source of [body, body.account, body.organization, body.oauth_account, body.profile]) {
      if (source == null) continue
      if (typeof source !== 'object' || Array.isArray(source)) throw invalid()
      for (const [key, value] of Object.entries(source)) {
        if (IDENTITY_TEXT_FIELDS.has(key) && value != null && typeof value !== 'string') throw invalid()
      }
    }
    const identity = flattenOauthIdentity(body)
    if (
      !oauthIdentityComplete(identity) ||
      !/^[^\s@]+@[^\s@]+$/.test(identity.email) ||
      !/^[A-Za-z0-9_-]+$/.test(identity.account_uuid) ||
      !/^[A-Za-z0-9_-]+$/.test(identity.org_uuid)
    )
      throw invalid()
    return identity
  } catch {
    throw invalid()
  }
}

export async function exchangeAuthorizationCodeWithoutGrove({
  code,
  codeVerifier,
  state = '',
  redirectUri = REDIRECT_URI,
  tokenUrls = [TOKEN_URL],
  proxyUrl = null,
  fetchImpl = null,
  timeoutMs = 15000,
  onTokenExchanged = null,
} = {}) {
  if (proxyUrl == null)
    throw new ExchangeError('proxy_required', 'A bound slot egress is required for OAuth exchange', 400)
  if (typeof proxyUrl !== 'string') throw new ExchangeError('proxy_invalid', 'Slot proxy URL is invalid', 400)
  if (!Array.isArray(tokenUrls) || !tokenUrls.length || tokenUrls.some((url) => !TRUSTED_TOKEN_URLS.has(url))) {
    throw new ExchangeError('token_url_invalid', 'OAuth token endpoint configuration is invalid', 400)
  }
  if (
    ![code, codeVerifier, redirectUri].every((value) => typeof value === 'string' && value.trim()) ||
    (state != null && typeof state !== 'string') ||
    (fetchImpl != null && typeof fetchImpl !== 'function') ||
    (onTokenExchanged != null && typeof onTokenExchanged !== 'function')
  )
    throw new ExchangeError('oauth_request_invalid', 'OAuth exchange parameters are invalid', 400)
  let agent
  if (proxyUrl !== '') {
    try {
      agent = createProxyAgent(proxyUrl)
    } catch {
      throw new ExchangeError('proxy_invalid', 'Slot proxy URL is invalid', 400)
    }
  }
  const requestedTimeout = Number(timeoutMs)
  const requestOptions = {
    agent,
    fetchFn: fetchImpl || fetch,
    timeoutMs: Number.isFinite(requestedTimeout) && requestedTimeout > 0 ? Math.min(requestedTimeout, 30000) : 15000,
  }
  const payload = {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
    ...(state ? { state } : {}),
  }
  try {
    const candidates = [...new Set(tokenUrls)]
    let token
    for (const [index, url] of candidates.entries()) {
      const response = await requestJson(
        url,
        {
          method: 'POST',
          headers: {
            ...OFFICIAL_CLI_HEADERS,
            'user-agent': TOKEN_UA,
            'content-type': 'application/json',
            accept: 'application/json',
          },
          body: JSON.stringify(payload),
        },
        { ...requestOptions, stage: 'token' },
      )
      if (response.status >= 300) {
        if ((response.status === 404 || response.status === 405) && index + 1 < candidates.length) continue
        throw httpFailure('token', response.status, response.body)
      }
      token = normalizeToken(response.body)
      break
    }
    if (onTokenExchanged) {
      try {
        await onTokenExchanged()
      } catch {
        throw new ExchangeError('oauth_session_consumption_failed', 'OAuth exchange session could not be consumed', 502)
      }
    }
    const response = await requestJson(
      CLAUDE_CLI_BOOTSTRAP_URL,
      {
        method: 'GET',
        headers: { ...OFFICIAL_CLI_HEADERS, ...bootstrapRequestHeaders(token.access_token) },
      },
      { ...requestOptions, stage: 'bootstrap' },
    )
    if (response.status >= 300) throw httpFailure('bootstrap', response.status, response.body)
    const identity = strictBootstrapIdentity(response.body)
    return applyOauthIdentity(
      {
        ...token,
        grove_settings: { status: 'skipped', reason: 'disabled_by_operator' },
      },
      identity,
    )
  } finally {
    agent?.destroy()
  }
}
