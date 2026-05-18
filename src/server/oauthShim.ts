import { randomBytes } from 'crypto';
import { Application, Request, Response } from 'express';

import { log } from '../logging/logger';

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
    if (grantType !== 'client_credentials') {
      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Only client_credentials is supported, got: ${grantType}`,
      });
      return;
    }
    // We don't actually validate the client_id/secret pair — anything that came
    // through /oauth/register (or that Snowflake otherwise has) is fine. Real
    // protection comes from MCP_BEARER_TOKEN possession at the bearer middleware.
    res.json({
      access_token: bearerToken,
      token_type: 'Bearer',
      expires_in: tokenLifetimeSeconds,
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
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    response_types_supported: ['token'],
    scopes_supported: ['mcp'],
    code_challenge_methods_supported: ['S256'],
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
