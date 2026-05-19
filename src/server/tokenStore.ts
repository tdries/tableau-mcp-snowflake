import { randomBytes } from 'crypto';

/**
 * In-memory token store for the OAuth shim.
 *
 * Each successful `/oauth/token` exchange (authorization_code,
 * client_credentials, or refresh) issues a fresh random access token and
 * refresh token, stored here. The bearer middleware validates incoming
 * `Authorization: Bearer …` headers against this store, so every Snowflake
 * user (or any other client) that goes through the OAuth dance ends up
 * with their own unique token.
 *
 * Trade-offs:
 * - In-memory only: a Railway redeploy wipes everything → all clients must
 *   re-Connect. Fine for small deployments; swap for SQLite / Redis if you
 *   want persistence across restarts.
 * - No way to tie a token back to a Snowflake *user* identity — Snowflake
 *   doesn't pass that to the MCP. We capture the DCR client_id and the
 *   client_name (if provided during /oauth/register) for crude audit only.
 */

export interface TokenInfo {
  accessToken: string;
  refreshToken: string;
  clientId: string;
  clientName?: string;
  issuedAt: number;
  expiresAt: number;
  refreshExpiresAt: number;
}

const ACCESS_TTL_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

const accessTokenStore = new Map<string, TokenInfo>();
const refreshTokenIndex = new Map<string, string>(); // refresh_token → access_token

export function issueToken(params: { clientId: string; clientName?: string }): TokenInfo {
  gcTokens();
  const now = Date.now();
  const info: TokenInfo = {
    accessToken: randomBytes(32).toString('hex'),
    refreshToken: randomBytes(32).toString('hex'),
    clientId: params.clientId,
    clientName: params.clientName,
    issuedAt: now,
    expiresAt: now + ACCESS_TTL_MS,
    refreshExpiresAt: now + REFRESH_TTL_MS,
  };
  accessTokenStore.set(info.accessToken, info);
  refreshTokenIndex.set(info.refreshToken, info.accessToken);
  return info;
}

export function refreshAccessToken(refreshToken: string): TokenInfo | null {
  gcTokens();
  const existingAccess = refreshTokenIndex.get(refreshToken);
  if (!existingAccess) return null;
  const existingInfo = accessTokenStore.get(existingAccess);
  if (!existingInfo) {
    refreshTokenIndex.delete(refreshToken);
    return null;
  }
  if (existingInfo.refreshExpiresAt < Date.now()) {
    revoke(existingAccess);
    return null;
  }

  // Rotate the access token, reuse the refresh token.
  accessTokenStore.delete(existingAccess);
  const now = Date.now();
  const next: TokenInfo = {
    ...existingInfo,
    accessToken: randomBytes(32).toString('hex'),
    issuedAt: now,
    expiresAt: now + ACCESS_TTL_MS,
  };
  accessTokenStore.set(next.accessToken, next);
  refreshTokenIndex.set(refreshToken, next.accessToken);
  return next;
}

export function validateAccessToken(token: string): TokenInfo | null {
  gcTokens();
  const info = accessTokenStore.get(token);
  if (!info) return null;
  if (info.expiresAt < Date.now()) return null;
  return info;
}

export function revoke(accessToken: string): void {
  const info = accessTokenStore.get(accessToken);
  if (!info) return;
  refreshTokenIndex.delete(info.refreshToken);
  accessTokenStore.delete(accessToken);
}

export function listIssuedTokens(): Array<Omit<TokenInfo, 'accessToken' | 'refreshToken'>> {
  // Don't leak the raw tokens — return metadata only.
  return Array.from(accessTokenStore.values()).map(({ accessToken: _a, refreshToken: _r, ...rest }) => rest);
}

function gcTokens(): void {
  const now = Date.now();
  for (const [token, info] of accessTokenStore) {
    if (info.refreshExpiresAt < now) {
      accessTokenStore.delete(token);
      refreshTokenIndex.delete(info.refreshToken);
    }
  }
}
