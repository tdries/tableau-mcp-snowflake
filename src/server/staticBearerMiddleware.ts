import { NextFunction, RequestHandler, Response } from 'express';

import { log } from '../logging/logger';
import { AuthenticatedRequest } from './oauth/types';
import { getHeader } from './requestUtils';
import { validateAccessToken } from './tokenStore';

interface BearerMiddlewareOptions {
  /** Optional static token that always validates — admin / curl backdoor. */
  envToken?: string;
  /** OAuth shim issuer URL; used to set a WWW-Authenticate hint on 401s. */
  issuer?: string;
}

export function staticBearerMiddleware(opts: BearerMiddlewareOptions): RequestHandler {
  const { envToken, issuer } = opts;
  if (!envToken && !issuer) {
    throw new Error(
      'staticBearerMiddleware requires at least one of: MCP_BEARER_TOKEN env var or OAUTH_SHIM_ISSUER',
    );
  }

  const resourceMetadataUrl = issuer
    ? `${issuer.replace(/\/+$/, '')}/.well-known/oauth-protected-resource`
    : '';
  const wwwAuthenticate = resourceMetadataUrl
    ? `Bearer realm="tableau-mcp", resource_metadata="${resourceMetadataUrl}"`
    : 'Bearer realm="tableau-mcp"';

  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const authHeader = getHeader(req, 'authorization');

    if (!authHeader) {
      reject(res, 'Missing Authorization header', wwwAuthenticate);
      return;
    }

    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) {
      reject(res, 'Authorization header must be in the form: Bearer <token>', wwwAuthenticate);
      return;
    }

    const presented = match[1].trim();

    // Path 1: env-var backdoor (kept for direct curl / admin testing).
    if (envToken && constantTimeEquals(presented, envToken)) {
      req.auth = { token: presented, clientId: 'static-env', scopes: [] };
      next();
      return;
    }

    // Path 2: tokens issued via the OAuth shim's /oauth/token endpoint.
    const issued = validateAccessToken(presented);
    if (issued) {
      req.auth = { token: presented, clientId: issued.clientId, scopes: [] };
      next();
      return;
    }

    log({
      message: 'Bearer auth rejected: token not recognized',
      level: 'info',
      logger: 'auth',
    });
    reject(res, 'Invalid bearer token', wwwAuthenticate);
  };
}

function reject(res: Response, description: string, wwwAuthenticate: string): void {
  res.setHeader('WWW-Authenticate', wwwAuthenticate);
  res.status(401).json({
    error: 'invalid_token',
    error_description: description,
  });
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
