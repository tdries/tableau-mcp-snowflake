import { NextFunction, RequestHandler, Response } from 'express';

import { log } from '../logging/logger';
import { AuthenticatedRequest } from './oauth/types';
import { getHeader } from './requestUtils';

export function staticBearerMiddleware(expectedToken: string): RequestHandler {
  if (!expectedToken) {
    throw new Error('staticBearerMiddleware requires a non-empty token');
  }

  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const authHeader = getHeader(req, 'authorization');

    if (!authHeader) {
      log({
        message: 'Static bearer auth rejected: missing Authorization header',
        level: 'info',
        logger: 'auth',
      });
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Missing Authorization header',
      });
      return;
    }

    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Authorization header must be in the form: Bearer <token>',
      });
      return;
    }

    const presented = match[1].trim();
    if (!constantTimeEquals(presented, expectedToken)) {
      log({
        message: 'Static bearer auth rejected: invalid token',
        level: 'info',
        logger: 'auth',
      });
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid bearer token',
      });
      return;
    }

    req.auth = {
      token: presented,
      clientId: 'static-bearer',
      scopes: [],
    };

    next();
  };
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
