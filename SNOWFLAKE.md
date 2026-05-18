# Calling this Tableau MCP from Snowflake Cortex Agents

Snowflake's `CREATE MCP SERVER` (the "MCP connection" button in Snowsight) requires the
remote MCP endpoint to authenticate inbound calls. The upstream Tableau MCP only
supports OAuth on its HTTP transport — that's hard to wire up from Snowflake.

This fork adds a **static bearer token** auth mode so Snowflake can call us with a
single shared secret in the `Authorization` header.

## 1. Deploy to Railway

1. Push this repo to GitHub.
2. In Railway, **New Project → Deploy from GitHub** and pick this repo.
3. Set these **Variables** on the Railway service:

   | Name | Value |
   | --- | --- |
   | `SERVER` | `https://your-tableau-cloud-pod.online.tableau.com` (or your Tableau Server URL) |
   | `SITE_NAME` | Your Tableau site name (the bit after `/site/` in the URL; empty string for the default site on Server) |
   | `PAT_NAME` | Name of a Tableau Personal Access Token |
   | `PAT_VALUE` | Value of that PAT |
   | `MCP_BEARER_TOKEN` | A long random string — generate with `openssl rand -hex 32` |
   | `TRANSPORT` | `http` (auto-defaulted when `MCP_BEARER_TOKEN` is set, but set explicitly for clarity) |

   Railway injects `PORT` automatically; the server listens on it.

4. Under **Settings → Networking**, click **Generate Domain**. You'll get a URL like
   `https://tableau-mcp-snowflake-production.up.railway.app`.

5. Your MCP endpoint is:

   ```
   https://<your-railway-domain>/tableau-mcp
   ```

## 2. Smoke-test the endpoint

```bash
# Should return 401 — proves the bearer check is active
curl -i https://<your-railway-domain>/tableau-mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ping","id":1}'

# Should return 200 with {"jsonrpc":"2.0","id":1,"result":{}}
curl -i https://<your-railway-domain>/tableau-mcp \
  -H 'Authorization: Bearer <MCP_BEARER_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"ping","id":1}'
```

## 3. Wire it up in Snowflake

In a Snowflake worksheet (you need `ACCOUNTADMIN` or a role with `CREATE INTEGRATION` /
`CREATE MCP SERVER` privileges):

```sql
-- 3a. Allow Snowflake to egress to Railway
CREATE OR REPLACE NETWORK RULE tableau_mcp_egress
  TYPE = HOST_PORT
  MODE = EGRESS
  VALUE_LIST = ('<your-railway-domain>:443');

-- 3b. Store the bearer token as a SECRET (don't paste it inline)
CREATE OR REPLACE SECRET tableau_mcp_token
  TYPE = GENERIC_STRING
  SECRET_STRING = '<MCP_BEARER_TOKEN>';

-- 3c. External access integration tying the two together
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION tableau_mcp_access
  ALLOWED_NETWORK_RULES = (tableau_mcp_egress)
  ALLOWED_AUTHENTICATION_SECRETS = (tableau_mcp_token)
  ENABLED = TRUE;

-- 3d. Register the MCP server
CREATE OR REPLACE MCP SERVER tableau_mcp
  FROM SPECIFICATION
  $$
  type: http
  url: https://<your-railway-domain>/tableau-mcp
  auth:
    type: bearer
    secret: tableau_mcp_token
  $$
  EXTERNAL_ACCESS_INTEGRATIONS = (tableau_mcp_access);
```

> The exact `CREATE MCP SERVER` syntax is still moving in Snowflake's preview docs —
> if your account uses a slightly different shape (e.g. a `HEADERS` block instead of
> `auth.type`), just make sure the request includes `Authorization: Bearer <secret>`
> and the rest of this guide still applies.

## 4. Attach to a Cortex Agent

When defining your Cortex Agent (in Snowflake Intelligence or via `CREATE AGENT`),
add `tableau_mcp` to the agent's tool list. The agent will then be able to call
every tool the Tableau MCP exposes (`list-workbooks`, `query-datasource`,
`get-view-image`, etc.).

## How auth actually works here

- **Snowflake → MCP server:** static bearer token (the `MCP_BEARER_TOKEN` env var).
  Enforced by `src/server/staticBearerMiddleware.ts` on every POST/GET/DELETE to
  `/tableau-mcp`.
- **MCP server → Tableau:** the PAT in `PAT_NAME` / `PAT_VALUE`. All tools run as
  that PAT's owner — there is no per-user delegation. Treat it like a service
  account.

If you ever need to rotate: change `MCP_BEARER_TOKEN` on Railway, then update the
`tableau_mcp_token` SECRET in Snowflake. No code change required.
