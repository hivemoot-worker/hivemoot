/**
 * GitHub authentication helpers.
 *
 * - generateAppJwt: creates a short-lived GitHub App JWT (RS256) for App-level API calls
 * - getOAuthStartConfig: validates the shared config needed by OAuth start routes
 * - buildOAuthAuthorizeRedirect: builds the OAuth redirect URL and binds the CSRF cookie
 * - exchangeOAuthCode: exchanges an OAuth authorization code for a user access token
 * - getAuthenticatedUser: fetches the authenticated GitHub user's identity
 * - getInstallation: fetches installation metadata using the App JWT
 * - checkOrgAdmin: verifies the user holds an "admin" role in the target org
 */

import { createSign } from "crypto";
import { NextResponse } from "next/server";
import { validateEnv } from "@/server/env";
import { OAUTH_STATE_BINDING_COOKIE } from "@/server/setup-session";

export const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
export const OAUTH_STATE_COOKIE_MAX_AGE = 600;

export interface OAuthStartConfig {
  githubClientId: string;
  redisRestUrl: string;
  redisRestToken: string;
  siteUrl: string;
}

export type OAuthStartConfigResult =
  | { ok: true; config: OAuthStartConfig }
  | {
      ok: false;
      reason:
        | "server_misconfiguration"
        | "github_oauth_not_configured"
        | "session_storage_not_configured";
    };

export function getOAuthStartConfig(): OAuthStartConfigResult {
  const env = validateEnv();
  if (!env.ok) {
    return { ok: false, reason: "server_misconfiguration" };
  }

  const { githubClientId, githubClientSecret, redisRestUrl, redisRestToken, siteUrl } = env.config;

  if (!githubClientId || !githubClientSecret) {
    return { ok: false, reason: "github_oauth_not_configured" };
  }
  if (!redisRestUrl || !redisRestToken) {
    return { ok: false, reason: "session_storage_not_configured" };
  }

  return {
    ok: true,
    config: { githubClientId, redisRestUrl, redisRestToken, siteUrl },
  };
}

export function buildOAuthAuthorizeRedirect({
  githubClientId,
  siteUrl,
  state,
  stateBinding,
}: {
  githubClientId: string;
  siteUrl: string;
  state: string;
  stateBinding: string;
}): NextResponse {
  const callbackUrl = `${siteUrl}/api/auth/github/callback`;
  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("client_id", githubClientId);
  authorizeUrl.searchParams.set("redirect_uri", callbackUrl);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("scope", "read:org");

  const response = NextResponse.redirect(authorizeUrl.toString());
  response.cookies.set(OAUTH_STATE_BINDING_COOKIE, stateBinding, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: OAUTH_STATE_COOKIE_MAX_AGE,
    path: "/",
  });

  return response;
}

// ---------------------------------------------------------------------------
// App JWT
// ---------------------------------------------------------------------------

/**
 * Generates a short-lived GitHub App JWT signed with the app's RSA private key.
 * Valid for 10 minutes; `iat` is backdated 60 s to absorb clock skew.
 */
export function generateAppJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ iat: now - 60, exp: now + 600, iss: appId }),
  ).toString("base64url");

  const signingInput = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  const signature = signer.sign(privateKeyPem, "base64url");

  return `${signingInput}.${signature}`;
}

// ---------------------------------------------------------------------------
// OAuth code exchange
// ---------------------------------------------------------------------------

/**
 * Exchanges a GitHub OAuth `code` for a user access token.
 * Throws on a GitHub-level error (e.g. bad code, expired code).
 */
export async function exchangeOAuthCode(
  code: string,
  clientId: string,
  clientSecret: string,
): Promise<string> {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
  });

  if (!response.ok) {
    throw new Error(`GitHub token endpoint returned ${response.status}`);
  }

  const data = (await response.json()) as { access_token?: string; error?: string; error_description?: string };

  if (data.error) {
    throw new Error(data.error_description ?? data.error);
  }
  if (!data.access_token) {
    throw new Error("No access_token in GitHub response");
  }

  return data.access_token;
}

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------

export interface GitHubUser {
  login: string;
  id: number;
}

/**
 * Fetches the identity of the user represented by `userToken`.
 */
export async function getAuthenticatedUser(userToken: string): Promise<GitHubUser> {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${userToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub /user returned ${response.status}`);
  }

  const data = (await response.json()) as { login: string; id: number };
  return { login: data.login, id: data.id };
}

// ---------------------------------------------------------------------------
// Installation metadata
// ---------------------------------------------------------------------------

export interface GitHubInstallation {
  account: {
    login: string;
    /** "Organization" or "User" */
    type: string;
  };
}

/**
 * Fetches installation metadata using the App JWT.
 * The installation endpoint is only accessible with App-level credentials,
 * not a user access token, which is why we generate the JWT here.
 */
export async function getInstallation(
  installationId: string,
  appJwt: string,
): Promise<GitHubInstallation> {
  const response = await fetch(
    `https://api.github.com/app/installations/${installationId}`,
    {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${appJwt}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    },
  );

  if (response.status === 404) {
    throw new Error(`Installation ${installationId} not found`);
  }
  if (!response.ok) {
    throw new Error(`GitHub /app/installations returned ${response.status}`);
  }

  const data = (await response.json()) as {
    account: { login: string; type: string };
  };
  return { account: { login: data.account.login, type: data.account.type } };
}

// ---------------------------------------------------------------------------
// Installation discovery (for users who already have the app installed)
// ---------------------------------------------------------------------------

export interface UserInstallation {
  id: number;
  app_id: number;
  account: {
    login: string;
    type: string;
  };
}

/**
 * Lists the authenticated user's installations of a specific GitHub App.
 *
 * Uses `GET /user/installations` which returns all app installations the user
 * can access, then filters by app_id so we only return our own.
 */
export async function getUserInstallations(
  userToken: string,
  appId: string,
): Promise<UserInstallation[]> {
  const response = await fetch("https://api.github.com/user/installations", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${userToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub /user/installations returned ${response.status}`);
  }

  const data = (await response.json()) as {
    installations: Array<{
      id: number;
      app_id: number;
      account: { login: string; type: string };
    }>;
  };

  return data.installations.filter((i) => String(i.app_id) === appId);
}

// ---------------------------------------------------------------------------
// Authorization checks
// ---------------------------------------------------------------------------

/**
 * Returns true if the user has the "admin" role in the target org.
 */
export async function checkOrgAdmin(userToken: string, org: string): Promise<boolean> {
  const response = await fetch(
    `https://api.github.com/user/memberships/orgs/${org}`,
    {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${userToken}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    },
  );

  if (response.status === 404 || response.status === 403) {
    // User is not a member or doesn't have permission to read membership
    return false;
  }
  if (!response.ok) {
    throw new Error(`GitHub org membership check returned ${response.status}`);
  }

  const data = (await response.json()) as { role: string; state: string };
  return data.role === "admin" && data.state === "active";
}
