/**
 * GET /api/auth/github/start-discover
 *
 * Initiates the GitHub OAuth flow for the "already installed" discovery path.
 *
 * Unlike /api/auth/github/start, this route does NOT require an installation_id.
 * It stores a "discover" sentinel in the OAuth state. After the user authorizes,
 * the callback detects the sentinel and resolves the real installation_id via
 * GET /user/installations.
 */

import { NextRequest, NextResponse } from "next/server";
import { buildOAuthAuthorizeRedirect, getOAuthStartConfig } from "@/server/github-auth";
import { getRedisClient } from "@/server/redis";
import { createOAuthState, DISCOVER_SENTINEL } from "@/server/setup-session";

const OAUTH_STATE_STORE_FAILED_CODE = "oauth_state_store_failed";

export async function GET(request: NextRequest) {
  const configResult = getOAuthStartConfig();
  if (!configResult.ok) {
    if (configResult.reason === "github_oauth_not_configured") {
      return NextResponse.json(
        { error: "GitHub OAuth is not configured on this server" },
        { status: 503 },
      );
    }
    if (configResult.reason === "session_storage_not_configured") {
      return NextResponse.json(
        { error: "Session storage is not configured on this server" },
        { status: 503 },
      );
    }
    return NextResponse.json({ error: "Server misconfiguration" }, { status: 503 });
  }

  const { githubClientId, redisRestUrl, redisRestToken, siteUrl } = configResult.config;

  const redis = getRedisClient(redisRestUrl, redisRestToken);

  let stateRecord: { state: string; stateBinding: string };
  try {
    stateRecord = await createOAuthState(DISCOVER_SENTINEL, redis);
  } catch {
    return NextResponse.json(
      { error: "Failed to store OAuth state", code: OAUTH_STATE_STORE_FAILED_CODE },
      { status: 503 },
    );
  }

  // Suppress Next.js static rendering check — request param is used
  // only to satisfy the dynamic route handler signature.
  void request;

  return buildOAuthAuthorizeRedirect({
    githubClientId,
    siteUrl,
    state: stateRecord.state,
    stateBinding: stateRecord.stateBinding,
  });
}
