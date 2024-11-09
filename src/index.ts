import { Context, Hono, Next } from 'hono'
import { env } from 'hono/adapter'

import { HTTPException } from 'hono/http-exception'
import { encodeState, tryDecodeState } from './shared/state'
import { rateLimit, RateLimitBinding, RateLimitKeyFunc } from '@elithrar/workers-hono-rate-limit'

// Types
type Bindings = {
  CLIENT_ID: string
  CLIENT_SECRET: string
  STATE_PASSWORD: string
  RATE_LIMITER: RateLimitBinding
}

// Constants
const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
const ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'

// Create Hono app
const app = new Hono<{ Bindings: Bindings }>()

// Your RateLimitKeyFunc returns the key to rate-limit on.
// It has access to everything in the Hono Context, including
// URL path parameters, query parameters, headers, the request body,
// and context values set by other middleware.
const getKey: RateLimitKeyFunc = (c: Context): string => {
  //use the ip address for rate limiting
	return c.req.header("cf-connecting-ip") || "";
};

// Create an instance of our rate limiter, passing it the Rate Limiting bindings
const rateLimiter = async (c: Context, next: Next) => {
	return await rateLimit(c.env.RATE_LIMITER, getKey)(c, next);
};

app.use("*", rateLimiter);

// Middleware to handle errors
app.onError((err, c) => {
  if (err instanceof HTTPException) {
    return c.json({ message: err.message }, err.status)
  }
  console.error('Unexpected error:', err)
  return c.json({ message: 'Internal Server Error' }, 500)
})

// Authorization initiation endpoint
app.get('/authorize', async (c) => {
  const { CLIENT_ID, STATE_PASSWORD } = c.env;
  const url = new URL(c.req.url)
  const redirectUri = url.searchParams.get('redirect_uri')

  if (!redirectUri) {
    throw new HTTPException(400, { message: '"redirect_uri" is required' })
  }

  const state = await encodeState(redirectUri, STATE_PASSWORD)
  const callbackUrl = `${url.origin}/authorized`

  const githubAuthUrl = new URL(AUTHORIZE_URL)
  githubAuthUrl.searchParams.set('client_id', CLIENT_ID)
  githubAuthUrl.searchParams.set('redirect_uri', callbackUrl)
  githubAuthUrl.searchParams.set('state', state)

  return c.redirect(githubAuthUrl.toString(), 302)
})

// Authorization callback endpoint
app.get('/authorized', async (c) => {
  const { CLIENT_ID, CLIENT_SECRET, STATE_PASSWORD } = c.env;
  const url = new URL(c.req.url)
  
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')

  if (!code || !state) {
    throw new HTTPException(400, { message: 'Missing required parameters' })
  }

  const returnUrl = await tryDecodeState(state, STATE_PASSWORD)

  // Exchange code for access token
  const response = await fetch(ACCESS_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'appsinprogress-oauth'
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      state
    })
  })

  if (!response.ok) {
    throw new HTTPException(500, { message: 'Unable to load token from GitHub' })
  }

  const data = await response.json<{
    access_token: string
    token_type: string
    scope: string
  }>()
  const accessToken = data.access_token

  // Encode the access token in state and redirect back to the app
  const redirectUrl = new URL(returnUrl)
  const session = await encodeState(
    accessToken,
    STATE_PASSWORD,
    Date.now() + 1000 * 60 * 60 * 24 * 365 // 1 year
  )
  redirectUrl.searchParams.set('appsinprogress-oauth', session)

  return c.redirect(redirectUrl.toString(), 302)
})

// Get access token from session
app.get('/token', async (c) => {
  const { STATE_PASSWORD } = c.env;
  const url = new URL(c.req.url)
  const session = url.searchParams.get('session')

  if (!session) {
    throw new HTTPException(400, { message: 'Session is required' })
  }

  const token = await tryDecodeState(session, STATE_PASSWORD)

  return c.json(
    { token },
    {
      headers: {
        'Cache-Control': 'private, max-age=600, s-maxage=600'
      }
    }
  )
})

export default app