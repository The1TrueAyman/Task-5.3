import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// ---- Anti-CSRF token ------------------------------------------------------
// The server requires an `x-csrf-token` header on every state-changing request.
// We fetch the token from GET /csrf-token (cross-origin pages can't read that
// response, thanks to CORS), keep it in memory, and attach it to each write.

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists and don't need a token.
const EXEMPT_URLS = ['/auth/login', '/auth/register']
// The token is bound to the session, so a new session needs a new token.
const SESSION_CHANGING_URLS = ['/auth/login', '/auth/register', '/auth/logout']

let csrfToken = null
let pending = null

export function resetCsrfToken() {
  csrfToken = null
  pending = null
}

async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

const matches = (url, list) => list.some(u => (url || '').includes(u))

api.interceptors.request.use(async config => {
  const method = (config.method || 'get').toLowerCase()
  if (!SAFE_METHODS.includes(method) && !matches(config.url, EXEMPT_URLS)) {
    config.headers.set('x-csrf-token', await getCsrfToken())
  }
  return config
})

api.interceptors.response.use(
  res => {
    if (matches(res.config?.url, SESSION_CHANGING_URLS)) resetCsrfToken()
    return res
  },
  async err => {
    const config = err.config
    // A stale token (e.g. the session changed) gets one retry with a fresh token.
    const isCsrfError = err.response?.status === 403 &&
      /csrf/i.test(err.response?.data?.message || '')
    if (isCsrfError && config && !config._csrfRetried) {
      config._csrfRetried = true
      resetCsrfToken()
      config.headers.set('x-csrf-token', await getCsrfToken())
      return api.request(config)
    }
    return Promise.reject(err)
  }
)
