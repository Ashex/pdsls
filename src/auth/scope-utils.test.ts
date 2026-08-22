import { describe, expect, it } from "vitest";

import {
  buildScopeString,
  GRANULAR_SCOPES,
  parseScopeString,
  scopeIdsToString,
} from "./scope-utils";

describe("GRANULAR_SCOPES", () => {
  it("includes the stratos scopes from the client package", () => {
    const byId = Object.fromEntries(GRANULAR_SCOPES.map((s) => [s.id, s.scope]));
    expect(byId["stratos-enrollment"]).toBe("repo:zone.stratos.actor.enrollment");
    expect(byId["stratos-posts"]).toBe("repo:zone.stratos.feed.post?action=create&action=delete");
    expect(byId["stratos-feed"]).toBe("rpc:zone.stratos.feedgen.getFeed?aud=*");
  });
});

describe("buildScopeString", () => {
  it("always starts with atproto", () => {
    expect(buildScopeString(new Set()).split(" ")[0]).toBe("atproto");
    expect(buildScopeString(new Set(["create", "stratos-posts"])).split(" ")[0]).toBe("atproto");
  });

  it("includes selected stratos scopes", () => {
    const result = buildScopeString(
      new Set(["stratos-enrollment", "stratos-posts", "stratos-feed"]),
    );
    expect(result).toContain("repo:zone.stratos.actor.enrollment");
    expect(result).toContain("repo:zone.stratos.feed.post?action=create&action=delete");
    expect(result).toContain("rpc:zone.stratos.feedgen.getFeed?aud=*");
  });

  it("omits unselected stratos scopes", () => {
    const result = buildScopeString(new Set(["create", "update"]));
    expect(result).not.toContain("zone.stratos");
  });
});

describe("scope id round-trip", () => {
  it("parseScopeString inverts scopeIdsToString", () => {
    const ids = new Set(["create", "delete", "stratos-enrollment", "stratos-posts"]);
    expect(parseScopeString(scopeIdsToString(ids))).toEqual(ids);
  });

  it("parseScopeString drops the atproto base scope", () => {
    expect(parseScopeString("atproto,create")).toEqual(new Set(["create"]));
    expect(parseScopeString("")).toEqual(new Set());
  });
});
