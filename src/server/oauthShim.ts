import { randomBytes } from 'crypto';
import { Application, Request, Response } from 'express';

import { log } from '../logging/logger';
import { issueToken, refreshAccessToken } from './tokenStore.js';

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
 * `API_USER_AUTHENTICATION` is set with one of its OAuth flavors.
 *
 * What this shim does:
 *   1. Advertises authorization-server metadata.
 *   2. Accepts any Dynamic Client Registration request and returns synthetic
 *      client credentials.
 *   3. Issues a UNIQUE bearer token on every successful /oauth/token exchange
 *      (authorization_code or client_credentials). Each Snowflake user that
 *      goes through "Connect" therefore receives their own token, validated
 *      by staticBearerMiddleware against the in-memory tokenStore.
 *
 * The static MCP_BEARER_TOKEN env var still works (backwards-compatible
 * admin/curl backdoor) but is no longer the only valid bearer.
 *
 * The shim does NOT authenticate any real user — there's no Tableau login
 * step. It just guarantees per-Connect uniqueness so different Snowflake
 * users carry distinct tokens.
 */
export function registerOAuthShim(app: Application, params: { issuer: string }): void {
  const { issuer } = params;

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
    const clientId = pickField(req, 'client_id') ?? 'unknown';

    if (grantType === 'refresh_token') {
      const refreshTok = pickField(req, 'refresh_token');
      if (!refreshTok) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token' });
        return;
      }
      const next = refreshAccessToken(refreshTok);
      if (!next) {
        log({
          message: 'OAuth shim: refresh_token unknown or expired',
          level: 'info',
          logger: 'auth',
        });
        res.status(400).json({
          error: 'invalid_grant',
          error_description: 'refresh_token is unknown or expired',
        });
        return;
      }
      log({
        message: `OAuth shim: refreshed access token for client ${next.clientId}`,
        level: 'info',
        logger: 'auth',
      });
      res.json({
        access_token: next.accessToken,
        token_type: 'Bearer',
        expires_in: Math.max(0, Math.floor((next.expiresAt - Date.now()) / 1000)),
        refresh_token: next.refreshToken,
        scope: 'mcp',
      });
      return;
    }

    if (grantType === 'authorization_code') {
      const code = pickField(req, 'code');
      if (!code) {
        res.status(400).json({ error: 'invalid_request', error_description: 'Missing code' });
        return;
      }
      gcCodes();
      const codeInfo = issuedCodes.get(code);
      if (!codeInfo) {
        log({
          message: 'OAuth shim: token request with unknown code, issuing bearer anyway',
          level: 'info',
          logger: 'auth',
        });
      } else {
        issuedCodes.delete(code);
      }
    } else if (grantType !== 'client_credentials') {
      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Got: ${grantType}. Supported: authorization_code, client_credentials, refresh_token`,
      });
      return;
    }

    // Fresh token per exchange — each Snowflake user's "Connect" gets their own.
    const issued = issueToken({ clientId });
    log({
      message: `OAuth shim: issued new access token for client ${clientId}`,
      level: 'info',
      logger: 'auth',
    });
    res.json({
      access_token: issued.accessToken,
      token_type: 'Bearer',
      expires_in: Math.max(0, Math.floor((issued.expiresAt - Date.now()) / 1000)),
      refresh_token: issued.refreshToken,
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
