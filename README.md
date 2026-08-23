# PDSlss - Atmosphere Explorer w/Stratos support

Lightweight web app to navigate [atproto](https://atproto.com/). This fork of
[pdsls](https://github.com/notjuliet/pdsls) is customized to support
[Stratos](https://github.com/NorthskySocial/stratos), a private permissioned
data service.

## Features

- Everything upstream pdsls does: browse PDSes, manage records, streaming,
  backlinks, labels, CAR exploration.
- Browse Stratos-enrolled repos: a shield toggle in the navbar switches
  between the public PDS view and the Stratos service view whenever both you
  and the browsed repo are enrolled on the same service.
- Record verification against the Stratos service signing key, and
  attestation verification for `zone.stratos.actor.enrollment` records.
- OAuth scope selection for Stratos enrollment, posts, and feeds.

## Hacking

You will need `bun` to get started. The `@northskysocial/stratos-client`
dependency is served from GitHub Packages, so exporting a token with
`read:packages` is required for installs:

```
export NODE_AUTH_TOKEN=<github token with read:packages>
bun install              # install deps
bun run dev              # runs local dev server
bun run build            # bundles the production app
bun run test             # runs vitest
bun run typecheck        # runs tsc
```

Set `APP_DOMAIN` (default: `pdsls.dev`) and `APP_PROTOCOL` (default: `https`) to configure the base URL used in the generated OAuth and OpenSearch metadata files.

The Docker image builds with `docker build --secret id=node_auth_token,src=<file with token> .`
and serves the static bundle with nginx.

## Credits

[pdsls](https://github.com/notjuliet/pdsls) - the upstream project\
[atcute](https://github.com/mary-ext/atcute) - atproto SDK\
[@skyware/firehose](https://github.com/skyware-js/firehose) - Firehose client
