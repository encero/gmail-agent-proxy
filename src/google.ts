import { createHash, randomBytes } from "node:crypto";
import type { Account, Store } from "./db.js";
import { stableId } from "./crypto.js";

const GMAIL_API = "https://gmail.googleapis.com/gmail/v1";
const OAUTH_TOKEN = "https://oauth2.googleapis.com/token";
const OAUTH_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";

interface OAuthClient { client_id: string; client_secret: string }

function clientFromStore(store: Store): OAuthClient {
  const raw = store.getSecret("oauth_client");
  if (!raw) throw Object.assign(new Error("OAuth client is not configured"), { statusCode: 409 });
  const parsed = JSON.parse(raw) as { web?: OAuthClient; installed?: OAuthClient };
  const client = parsed.web ?? parsed.installed;
  if (!client?.client_id || !client.client_secret) throw new Error("Stored OAuth client is invalid");
  return client;
}

export function validateAndNormalizeClient(raw: string): string {
  const parsed = JSON.parse(raw) as { web?: OAuthClient; installed?: OAuthClient };
  const client = parsed.web ?? parsed.installed;
  if (!client?.client_id || !client.client_secret) throw new Error("Expected a Google OAuth client JSON file with web or installed credentials");
  return JSON.stringify({ web: { client_id: client.client_id, client_secret: client.client_secret } });
}

export function beginOAuth(store: Store, redirectUri: string): string {
  const client = clientFromStore(store);
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = store.createOauthState(verifier);
  const query = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: GMAIL_SCOPE,
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  return `${OAUTH_AUTH}?${query}`;
}

export async function finishOAuth(store: Store, redirectUri: string, code: string, state: string): Promise<{ id: string; email: string }> {
  const verifier = store.consumeOauthState(state);
  if (!verifier) throw Object.assign(new Error("OAuth state is invalid, expired, or already used"), { statusCode: 400 });
  const client = clientFromStore(store);
  const body = new URLSearchParams({ code, client_id: client.client_id, client_secret: client.client_secret, redirect_uri: redirectUri, grant_type: "authorization_code", code_verifier: verifier });
  const response = await fetch(OAUTH_TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  const tokens = await response.json() as { access_token?: string; refresh_token?: string; scope?: string; error_description?: string };
  if (!response.ok || !tokens.access_token || !tokens.refresh_token) throw Object.assign(new Error(tokens.error_description ?? "Google did not return an offline refresh token"), { statusCode: 502 });
  const profileResponse = await fetch(`${GMAIL_API}/users/me/profile`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  const profile = await profileResponse.json() as { emailAddress?: string };
  if (!profileResponse.ok || !profile.emailAddress) throw Object.assign(new Error("Could not read the linked Gmail profile"), { statusCode: 502 });
  const id = stableId(profile.emailAddress);
  store.upsertAccount(id, profile.emailAddress, tokens.refresh_token, tokens.scope ?? GMAIL_SCOPE);
  return { id, email: profile.emailAddress };
}

async function accessToken(store: Store, account: Account): Promise<string> {
  const client = clientFromStore(store);
  const body = new URLSearchParams({ client_id: client.client_id, client_secret: client.client_secret, refresh_token: account.refreshToken, grant_type: "refresh_token" });
  const response = await fetch(OAUTH_TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
  const json = await response.json() as { access_token?: string; error_description?: string };
  if (!response.ok || !json.access_token) throw Object.assign(new Error(json.error_description ?? "Could not refresh Google access token"), { statusCode: 502 });
  return json.access_token;
}

export class GoogleError extends Error {
  constructor(readonly statusCode: number, readonly payload: unknown) { super(`Google API request failed (${statusCode})`); }
}

export async function gmailRequest(store: Store, account: Account, path: string, options: { method?: "GET" | "POST" | "PATCH" | "DELETE"; query?: URLSearchParams; body?: unknown } = {}): Promise<unknown> {
  if (!path.startsWith("/users/me/")) throw new Error("Internal policy violation: Google path must be fixed to users/me");
  const token = await accessToken(store, account);
  const url = `${GMAIL_API}${path}${options.query?.size ? `?${options.query}` : ""}`;
  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: { authorization: `Bearer ${token}`, ...(options.body === undefined ? {} : { "content-type": "application/json" }) },
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new GoogleError(response.status, payload);
  return payload;
}
