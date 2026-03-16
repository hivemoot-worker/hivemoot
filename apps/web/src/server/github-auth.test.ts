import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/server/env", () => ({
  validateEnv: vi.fn(),
}));

vi.mock("@/server/setup-session", () => ({
  OAUTH_STATE_BINDING_COOKIE: "oauth_state_binding",
}));

import { validateEnv } from "@/server/env";
import { buildOAuthAuthorizeRedirect, getOAuthStartConfig } from "./github-auth";

const VALID_ENV = {
  githubClientId: "Iv1.test",
  githubClientSecret: "secret",
  redisRestUrl: "https://example.upstash.io",
  redisRestToken: "test-token",
  siteUrl: "https://example.com",
  nodeEnv: "production",
  githubAppId: "99",
  githubAppPrivateKey: "-----BEGIN RSA PRIVATE KEY-----",
  byokActiveKeyVersion: "v1",
  byokMasterKeysJson: '{"v1":"' + "a".repeat(64) + '"}',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(validateEnv).mockReturnValue({ ok: true, config: { ...VALID_ENV } });
});

describe("getOAuthStartConfig", () => {
  it("returns the shared config when OAuth start env is present", () => {
    expect(getOAuthStartConfig()).toEqual({
      ok: true,
      config: {
        githubClientId: "Iv1.test",
        redisRestUrl: "https://example.upstash.io",
        redisRestToken: "test-token",
        siteUrl: "https://example.com",
      },
    });
  });

  it("reports server misconfiguration when validateEnv fails", () => {
    vi.mocked(validateEnv).mockReturnValue({ ok: false, missing: ["GITHUB_CLIENT_ID"] });

    expect(getOAuthStartConfig()).toEqual({
      ok: false,
      reason: "server_misconfiguration",
    });
  });

  it("reports GitHub OAuth config errors separately from Redis errors", () => {
    vi.mocked(validateEnv).mockReturnValue({
      ok: true,
      config: { ...VALID_ENV, githubClientId: undefined, githubClientSecret: undefined },
    });
    expect(getOAuthStartConfig()).toEqual({
      ok: false,
      reason: "github_oauth_not_configured",
    });

    vi.mocked(validateEnv).mockReturnValue({
      ok: true,
      config: { ...VALID_ENV, redisRestUrl: undefined, redisRestToken: undefined },
    });
    expect(getOAuthStartConfig()).toEqual({
      ok: false,
      reason: "session_storage_not_configured",
    });
  });
});

describe("buildOAuthAuthorizeRedirect", () => {
  it("builds the GitHub authorize redirect and binds the state cookie", () => {
    const response = buildOAuthAuthorizeRedirect({
      githubClientId: "Iv1.test",
      siteUrl: "https://example.com",
      state: "deadbeef".repeat(8),
      stateBinding: "cafebabe".repeat(8),
    });

    expect(response.status).toBe(307);

    const location = response.headers.get("location")!;
    expect(location).toMatch(/^https:\/\/github\.com\/login\/oauth\/authorize/);
    expect(location).toContain("client_id=Iv1.test");
    expect(location).toContain("state=deadbeef");
    expect(location).toContain(encodeURIComponent("https://example.com/api/auth/github/callback"));
    expect(location).toContain("scope=read%3Aorg");

    const setCookie = response.headers.get("set-cookie")!;
    expect(setCookie).toContain("oauth_state_binding=");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Max-Age=600");
  });
});
