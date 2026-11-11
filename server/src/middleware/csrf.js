import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// 1. The client calls GET /api/csrf-token. The server sets a signed CSRF cookie
//    and returns the matching token in the JSON body.
// 2. On every state-changing request the client echoes the token in the
//    `x-csrf-token` header. The server checks that the header token matches the
//    cookie AND is bound (HMAC) to the current session.
//
// Why an attacker can't forge it:
//  - A cross-site <form> can't set custom headers, so the header is missing.
//  - CORS (locked to the client origin) stops the attacker's page from reading
//    the /api/csrf-token response, so it never learns the token.
//  - The token is HMAC-bound to the session (the auth cookie), so a token from a
//    different session or a planted cookie isn't valid.

const isProd = process.env.NODE_ENV === 'production';

// Pre-auth routes run before a session exists, so they're exempt.
const EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/register']);

const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read the secret lazily so env vars loaded later (dotenv, tests) are picked up.
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind each token to the user's session. Before login there's no auth cookie,
  // so the identifier is empty and a token must be fetched again after login.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  cookieName: isProd ? '__Host-x-csrf-token' : 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    path: '/'
  },
  // GET/HEAD/OPTIONS are "safe" and aren't checked.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Pre-auth routes run before a session exists, so they're exempt.
  skipCsrfProtection: (req) => EXEMPT_PATHS.has(req.path)
});

export const csrfProtection = doubleCsrfProtection;

// GET /api/csrf-token — issue a token for the current session.
export function csrfTokenHandler(req, res) {
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
