import { Client } from "@atcute/client";
import type { OAuthUserAgent } from "@atcute/oauth-browser-client";
import { createServiceFetchHandler } from "@northskysocial/stratos-client";

import { stratosMode, targetEnrollment } from "./state";

// ngrok free tier returns an HTML interstitial for browser User-Agents
const DEV_TUNNEL_HEADERS = { "ngrok-skip-browser-warning": "1" };

/**
 * Creates a Client routed to a Stratos service using the agent's DPoP
 * credentials. When no explicit serviceUrl is given, routes to the browsed
 * repo's service if effective Stratos mode is on, otherwise falls back to
 * the agent's default PDS routing.
 */
export const createServiceClient = (agent: OAuthUserAgent, serviceUrl?: string): Client => {
  const url = serviceUrl ?? (stratosMode() ? targetEnrollment()?.service : undefined);
  if (url) {
    return new Client({
      handler: createServiceFetchHandler(agent.handle.bind(agent), url, {
        headers: DEV_TUNNEL_HEADERS,
      }),
    });
  }
  return new Client({ handler: agent });
};
