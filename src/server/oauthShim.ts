import { randomBytes } from 'crypto';
import { Application, Request, Response } from 'express';

import { log } from '../logging/logger';

// In-memory store of authorization codes we've issued. The shim doesn't
// authenticate any real user — possession of MCP_BEARER_TOKEN is the real
// trust boundary — so we just need to round-trip a code so the OAuth
// authorization_code dance completes.
const issuedCodes = new Map<string, { expiresAt: number }>();
const CODE_TTL_MS = 10 * 60 * 1000;

function gcCodes(): void {
  const now = Date.now();
  for (const [code, info] of issuedCodes) {
    if (info.expiresAt < now) {
      issuedCodes.delete(code);
    }
  }
}

/**
 * Minimal OAuth 2.0 authorization-server shim for Snowflake's `external_mcp`
 * API integration. Snowflake refuses to register an external MCP server unless
 * `API_USER_AUTHENTICATION` is set, and the only types that fit a
 * machine-to-machine Cortex Agent are OAUTH_DYNAMIC_CLIENT / OAUTH_CLIENT_CREDENTIALS.
 *
 * Real OAuth would require user-interactive auth flows we don't want. Instead
 * this shim:
 *   1. Advertises an authorization-server metadata document.
 *   2. Accepts any Dynamic Client Registration request and returns synthetic
 *      client credentials.
 *   3. Accepts client_credentials token grants and returns the shared bearer
 *      token (the same MCP_BEARER_TOKEN our staticBearerMiddleware validates).
 *
 * The result: Snowflake completes DCR + client_credentials happily, then sends
 * every MCP call with `Authorization: Bearer <MCP_BEARER_TOKEN>`, which the
 * existing middleware accepts. No real user identity is established — this is
 * service-account-style auth, gated on possession of MCP_BEARER_TOKEN.
 */
export function registerOAuthShim(app: Application, params: { issuer: string; bearerToken: string }): void {
  const { issuer, bearerToken } = params;
  const tokenLifetimeSeconds = 60 * 60;

  app.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
    res.json(buildMetadata(issuer));
  });
  // Some clients hit the protected-resource variant first.
  app.get('/.well-known/oauth-protected-resource', (_req: Request, res: Response) => {
    res.json({
      resource: issuer,
      authorization_servers: [issuer],
      bearer_methods_supported: ['header'],
    });
  });
  // Same metadata is sometimes requested under the MCP base path.
  app.get('/tableau-mcp/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
    res.json(buildMetadata(issuer));
  });
  app.get('/tableau-mcp/.well-known/oauth-protected-resource', (_req: Request, res: Response) => {
    res.json({
      resource: issuer,
      authorization_servers: [issuer],
      bearer_methods_supported: ['header'],
    });
  });

  // Stubs so probes for these advertised endpoints don't 404.
  app.get('/.well-known/jwks.json', (_req: Request, res: Response) => {
    res.json({ keys: [] });
  });
  app.get('/oauth/authorize', (req: Request, res: Response) => {
    // Snowflake's external_mcp uses the authorization_code grant: it sends
    // the user's browser here, we issue a code, redirect back to the
    // Snowsight callback. There's no real user to authenticate -- possession
    // of MCP_BEARER_TOKEN is the trust boundary -- so we just round-trip.
    const redirectUri = pickField(req, 'redirect_uri');
    const state = pickField(req, 'state');
    if (!redirectUri) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing redirect_uri',
      });
      return;
    }
    gcCodes();
    const code = randomBytes(24).toString('hex');
    issuedCodes.set(code, { expiresAt: Date.now() + CODE_TTL_MS });

    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    log({
      message: `OAuth shim: issuing code, redirecting to ${url.origin}${url.pathname}`,
      level: 'info',
      logger: 'auth',
    });
    res.redirect(302, url.toString());
  });
  app.post('/oauth/revoke', (_req: Request, res: Response) => {
    // RFC 7009: always 200 — even for unknown tokens.
    res.status(200).end();
  });

  app.post('/oauth/register', (req: Request, res: Response) => {
    const clientId = randomBytes(16).toString('hex');
    const clientSecret = randomBytes(32).toString('hex');
    log({
      message: `OAuth shim: registered new client ${clientId}`,
      level: 'info',
      logger: 'auth',
    });
    res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'client_secret_basic',
      ...(req.body && typeof req.body === 'object' ? req.body : {}),
    });
  });

  app.post('/oauth/token', (req: Request, res: Response) => {
    const grantType = pickField(req, 'grant_type');
    if (grantType === 'authorization_code') {
      const code = pickField(req, 'code');
      if (!code) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing code',
        });
        return;
      }
      gcCodes();
      const codeInfo = issuedCodes.get(code);
      if (!codeInfo) {
        // Unknown / expired code. Be lenient — the shim's trust boundary is
        // the bearer middleware, not code validation — but still log it.
        log({
          message: `OAuth shim: token request with unknown code, issuing bearer anyway`,
          level: 'info',
          logger: 'auth',
        });
      } else {
        issuedCodes.delete(code); // single-use
      }
    } else if (grantType === 'refresh_token') {
      // Snowflake will try this when the access token expires. Return a fresh one.
    } else if (grantType !== 'client_credentials') {
      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Got: ${grantType}. Supported: authorization_code, client_credentials, refresh_token`,
      });
      return;
    }
    // We don't validate client_id/secret — possession of MCP_BEARER_TOKEN
    // remains the actual trust boundary at the bearer middleware.
    res.json({
      access_token: bearerToken,
      token_type: 'Bearer',
      expires_in: tokenLifetimeSeconds,
      refresh_token: bearerToken,
      scope: 'mcp',
    });
  });

  log({
    message: `OAuth shim mounted at ${issuer} (/.well-known/oauth-authorization-server, /oauth/register, /oauth/token)`,
    level: 'info',
    logger: 'startup',
  });
}

function buildMetadata(issuer: string): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256', 'plain'],
    scopes_supported: ['mcp', 'openid'],
    subject_types_supported: ['public'],
    service_documentation: 'https://github.com/tdries/tableau-mcp-snowflake',
  };
}

function pickField(req: Request, name: string): string | undefined {
  const body = req.body as Record<string, unknown> | undefined;
  if (body && typeof body[name] === 'string') {
    return body[name] as string;
  }
  const query = req.query as Record<string, unknown> | undefined;
  if (query && typeof query[name] === 'string') {
    return query[name] as string;
  }
  return undefined;
}
