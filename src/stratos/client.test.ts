import { Client } from "@atcute/client";
import type { OAuthUserAgent } from "@atcute/oauth-browser-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => store.set(k, String(v)),
  removeItem: (k: string) => store.delete(k),
  get stratosActive() {
    return store.get("stratosActive");
  },
  set stratosActive(v: string | undefined) {
    if (v !== undefined) store.set("stratosActive", String(v));
  },
});

const { createServiceClient } = await import("./client");
const { setStratosActive, setStratosEnrollment, setTargetEnrollment } = await import("./state");

const PATH = "/xrpc/com.atproto.repo.describeRepo";
const OWN_SERVICE = "https://stratos.nerv.tokyo.jp";
const OTHER_SERVICE = "https://stratos.seele.example";

const makeEnrollment = (service: string) => ({
  service,
  boundaries: [],
  signingKey: "did:key:zUserKey",
  attestation: { sig: new Uint8Array([1, 2, 3]), signingKey: "did:key:zServiceKey" },
  createdAt: "1995-10-04T00:00:00Z",
  rkey: `did:web:${new URL(service).hostname}`,
});

type MockAgent = OAuthUserAgent & {
  lastUrl: string | undefined;
  lastInit: RequestInit | undefined;
};

const makeMockAgent = (): MockAgent => {
  const agent = {
    lastUrl: undefined as string | undefined,
    lastInit: undefined as RequestInit | undefined,
    handle: vi.fn(async (url: string, init?: RequestInit) => {
      agent.lastUrl = url;
      agent.lastInit = init;
      return new Response(null, { status: 200 });
    }),
  } as unknown as MockAgent;
  return agent;
};

/** puts both sides on the same service, so stratosMode() is effective. */
const enrollBothOn = (service: string) => {
  setStratosActive(true);
  setStratosEnrollment(makeEnrollment(service));
  setTargetEnrollment(makeEnrollment(service));
};

beforeEach(() => {
  setStratosActive(false);
  setStratosEnrollment(undefined);
  setTargetEnrollment(undefined);
});

describe("createServiceClient", () => {
  it("always returns a Client instance", () => {
    expect(createServiceClient(makeMockAgent())).toBeInstanceOf(Client);

    enrollBothOn(OWN_SERVICE);
    expect(createServiceClient(makeMockAgent())).toBeInstanceOf(Client);
  });

  it("routes to the browsed service origin when Stratos mode is effective", async () => {
    enrollBothOn(OWN_SERVICE);
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    expect(agent.lastUrl).toBeDefined();
    expect(new URL(agent.lastUrl!).origin).toBe(new URL(OWN_SERVICE).origin);
  });

  it("passes the raw pathname to the agent when Stratos is inactive", async () => {
    setStratosActive(false);
    setStratosEnrollment(makeEnrollment(OWN_SERVICE));
    setTargetEnrollment(makeEnrollment(OWN_SERVICE));
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    expect(agent.lastUrl).toBe(PATH);
  });

  it("passes the raw pathname when the browsed repo is not enrolled", async () => {
    setStratosActive(true);
    setStratosEnrollment(makeEnrollment(OWN_SERVICE));
    setTargetEnrollment(null);
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    expect(agent.lastUrl).toBe(PATH);
  });

  it("passes the raw pathname when the user is not enrolled", async () => {
    setStratosActive(true);
    setStratosEnrollment(null);
    setTargetEnrollment(makeEnrollment(OWN_SERVICE));
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    expect(agent.lastUrl).toBe(PATH);
  });

  it("does not route when the two enrollments target different services", async () => {
    setStratosActive(true);
    setStratosEnrollment(makeEnrollment(OWN_SERVICE));
    setTargetEnrollment(makeEnrollment(OTHER_SERVICE));
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    expect(agent.lastUrl).toBe(PATH);
  });

  it("routes to an explicit serviceUrl even when Stratos mode is off", async () => {
    setStratosActive(false);
    const agent = makeMockAgent();

    await createServiceClient(agent, OTHER_SERVICE).handler(PATH, {});

    expect(new URL(agent.lastUrl!).origin).toBe(new URL(OTHER_SERVICE).origin);
  });

  it("prefers an explicit serviceUrl over the browsed repo's service", async () => {
    enrollBothOn(OWN_SERVICE);
    const agent = makeMockAgent();

    await createServiceClient(agent, OTHER_SERVICE).handler(PATH, {});

    expect(new URL(agent.lastUrl!).origin).toBe(new URL(OTHER_SERVICE).origin);
  });

  it("sets the dev tunnel bypass header on routed requests", async () => {
    enrollBothOn(OWN_SERVICE);
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {});

    const headers = new Headers(agent.lastInit?.headers);
    expect(headers.get("ngrok-skip-browser-warning")).toBe("1");
  });

  it("preserves per-request headers while routing", async () => {
    enrollBothOn(OWN_SERVICE);
    const agent = makeMockAgent();

    await createServiceClient(agent).handler(PATH, {
      headers: { accept: "application/json" },
    });

    const headers = new Headers(agent.lastInit?.headers);
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("ngrok-skip-browser-warning")).toBe("1");
  });
});
