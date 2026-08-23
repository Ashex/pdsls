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

const {
  serviceMismatch,
  setStratosActive,
  setStratosEnrollment,
  setTargetEnrollment,
  stratosActive,
  stratosMode,
} = await import("./state");

const enrollment = (service: string) => ({
  service,
  boundaries: [],
  signingKey: "did:key:zTest",
  attestation: { sig: new Uint8Array([1]), signingKey: "did:key:zService" },
  createdAt: "2025-01-01T00:00:00Z",
  rkey: `did:web:${new URL(service).hostname}`,
});

beforeEach(() => {
  setStratosActive(false);
  setStratosEnrollment(undefined);
  setTargetEnrollment(undefined);
});

describe("stratosActive persistence", () => {
  it("persists the preference to localStorage", () => {
    setStratosActive(true);
    expect(store.get("stratosActive")).toBe("true");
    setStratosActive(false);
    expect(store.get("stratosActive")).toBe("false");
  });

  it("supports functional updates", () => {
    setStratosActive(false);
    setStratosActive((v) => !v);
    expect(stratosActive()).toBe(true);
  });
});

describe("stratosMode (effective mode)", () => {
  it("is off without enrollments even when the preference is on", () => {
    setStratosActive(true);
    expect(stratosMode()).toBe(false);
  });

  it("is off when only the user is enrolled", () => {
    setStratosActive(true);
    setStratosEnrollment(enrollment("https://stratos.example.com"));
    expect(stratosMode()).toBe(false);
  });

  it("is on when both are enrolled on the same service", () => {
    setStratosActive(true);
    setStratosEnrollment(enrollment("https://stratos.example.com"));
    setTargetEnrollment(enrollment("https://stratos.example.com"));
    expect(stratosMode()).toBe(true);
  });

  it("is off when the preference is off", () => {
    setStratosActive(false);
    setStratosEnrollment(enrollment("https://stratos.example.com"));
    setTargetEnrollment(enrollment("https://stratos.example.com"));
    expect(stratosMode()).toBe(false);
  });

  it("keeps the preference but disables mode on non-enrolled repos", () => {
    setStratosActive(true);
    setStratosEnrollment(enrollment("https://stratos.example.com"));
    setTargetEnrollment(enrollment("https://stratos.example.com"));
    expect(stratosMode()).toBe(true);

    // navigate to a public (non-enrolled) repo
    setTargetEnrollment(null);
    expect(stratosMode()).toBe(false);
    expect(stratosActive()).toBe(true);

    // navigate back to an enrolled repo
    setTargetEnrollment(enrollment("https://stratos.example.com"));
    expect(stratosMode()).toBe(true);
  });

  it("is off on service mismatch", () => {
    setStratosActive(true);
    setStratosEnrollment(enrollment("https://stratos-a.example.com"));
    setTargetEnrollment(enrollment("https://stratos-b.example.com"));
    expect(serviceMismatch()).toBe(true);
    expect(stratosMode()).toBe(false);
  });
});
