/**
 * GET /api/auth/github/start
 *
 * Initiates the GitHub OAuth flow for a given installation.
 *
 * Expects: ?installation_id=<numeric id>
 *
 * - Validates the installation_id is present
 * - Generates a cryptographically random state nonce bound to the installation
 * - Stores the state in Redis with a 10-minute TTL
 * - Redirects the browser to GitHub's OAuth authorization URL
 *
 * All error paths that occur during a browser-initiated flow redirect to
 * /setup/error with a code param instead of returning raw JSON.
 */

import { NextRequest, NextResponse } from "next/server";
import { buildOAuthAuthorizeRedirect, getOAuthStartConfig } from "@/server/github-auth";
import { getRedisClient } from "@/server/redis";
import { createOAuthState } from "@/server/setup-session";

function setupErrorRedirect(
  request: NextRequest,
  code: string,
  installationId?: string,
): NextResponse {
  const url = new URL("/setup/error", request.url);
  url.searchParams.set("code", code);
  if (installationId) url.searchParams.set("installation_id", installationId);
  return NextResponse.redirect(url.toString());
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const installationId = searchParams.get("installation_id") ?? undefined;

  const configResult = getOAuthStartConfig();
  if (!configResult.ok) {
    return setupErrorRedirect(request, "server_misconfiguration", installationId);
  }

  const { githubClientId, redisRestUrl, redisRestToken, siteUrl } = configResult.config;

  if (!installationId || !/^\d+$/.test(installationId)) {
    // Missing installation_id is a malformed link — redirect to setup root without an id
    return NextResponse.redirect(new URL("/setup", request.url).toString());
  }

  const redis = getRedisClient(redisRestUrl, redisRestToken);

  let stateRecord: { state: string; stateBinding: string };
  try {
    stateRecord = await createOAuthState(installationId, redis);
  } catch (err) {
    console.error("[oauth-start] Failed to store OAuth state", { installationId, error: err });
    return setupErrorRedirect(request, "oauth_state_store_failed", installationId);
  }

  return buildOAuthAuthorizeRedirect({
    githubClientId,
    siteUrl,
    state: stateRecord.state,
    stateBinding: stateRecord.stateBinding,
  });
}
