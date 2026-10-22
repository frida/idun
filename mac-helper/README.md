# idun-mac-helper

Produces, on macOS, the Apple identity primitives a Linux Idun client needs but
cannot yet compute itself: NAC validation data, FairPlay activation signatures,
the Mac's device identity, and Anisette headers, all bound to real Apple
hardware. It only computes; Idun makes every request to Apple itself.

A Frida agent (`agent/`, compiled to `idun-mac-agent.js`) loads into the live
`identityservicesd`, `apsd` and `akd` and drives Apple's own code by name, so it
needs no entitlements, no hardcoded binary offsets, and no System Integrity
Protection changes beyond what Frida injection already requires. The raw
primitives it calls (`NACSign`, the FairPlay signer) are located at runtime by
anchoring on an Objective-C method and matching the call site, so they survive
OS updates and refuse loudly rather than misbehave if the layout ever changes.

## Build the agent

```sh
cd agent && npm install && npm run build
```

## Run the oracle

`idun-mac-oracle.py` is the single endpoint the Linux client talks to. It spawns
`idun-mac-host.py`, a plain injectable process that loads the daemon frameworks,
and injects the agent into it; `akd` is attached lazily the first time Anisette
is asked for.

```sh
./idun-mac-oracle.py --listen 127.0.0.1:8080
```

- `GET /device-info` — the Mac's identity and push User-Agent.
- `GET /anisette` — Anisette headers (`X-Apple-I-MD` and friends) minted by the
  logged-in user's `akd`.
- `POST /fairplay-sign` — signs the body the way `apsd` signs its activation
  info, returning the RSA-SHA1 `signature` and FairPlay `certificate_chain`.
- `POST /validation/begin`, `POST /validation/continue` — drive Apple's NAC
  validation handshake step by step, so Idun makes the Apple requests itself and
  the agent only signs, ending in the validation-data blob. It is valid for
  about 15 minutes; Idun fetches a fresh one at registration time.

This is a stop-gap until Idun can produce these primitives on Linux itself.
