# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository, or write to
**fabrizio.salmi@gmail.com**. Please do not open a public issue first.

Tell us what you did, what happened, and what you expected instead. A proof of
concept helps; a working exploit is not required and never expected against a
third party's site.

Expect an acknowledgement within 5 working days. This is a one-person project,
so a fix may take longer than that, and we would rather tell you a real date
than a reassuring one.

## What counts as a vulnerability here

This engine's whole claim is that it observes passively and reports only what
it saw. Anything that breaks either half of that sentence is in scope:

- **Bypassing the target check.** The API resolves a hostname and requires every
  address behind it to be public. While a scan runs, the browser, the robots.txt
  reader and the TLS probe reach the network only through an egress proxy that
  resolves each name itself, requires public addresses and connects to the
  address it checked; the addresses actually reached are then checked a last
  time. A request that reaches a non-public address by any route (a redirect, a
  sub-resource, a WebSocket, a rebound name, a document or robots.txt URL taken
  from the page) turns an instance into an SSRF proxy against its own network —
  this is the most serious class of bug in the project.
- **Bypassing `SCANPRIVACY_API_KEY`**, or reaching a `/v1` route without one.
- **Escaping the bind guard**, so that `scanprivacy serve` listens on a non-loopback
  interface with no key configured.
- **Forging evidence.** Anything that makes `scanprivacy verify` accept a JSON file
  whose digests do not describe the analysis it claims, or that makes two
  different observations produce the same configuration digest.
- **Reporting a state that was never observed.** A finding emitted from a failed
  read, an absence asserted from a swallowed exception, a `PASS` where nothing
  was checked. We treat this as a security bug and not a correctness one,
  because the output is used as a compliance record.
- Writing outside the output directory the operator named; command injection via
  a URL, a rule id, or a locale; a crafted page that reaches the report renderer.

## What does not count

- **Disagreeing with a finding.** That is an issue, and a welcome one, but it is
  not a vulnerability. `scanprivacy remediation <rule-id>` explains what the rule
  claims to have observed.
- **`scanprivacy scan http://localhost:8000` working.** The command line deliberately
  has no public-address check: there the operator chose the target, and refusing
  to scan a site before it is deployed would break the ordinary use. The check
  exists on the API, where the caller may be someone else.
- **An unauthenticated `/healthz`.** It reports the security posture and the
  source location, never the key, and a liveness probe that needs a credential
  stops working the day the credential rotates.
- **Missing rate limits on an instance you run yourself.** Concurrency and
  in-flight caps are tunable and documented; choosing them is the operator's.

## If your site received a request from this engine

You can identify us in your logs by the User-Agent, which names the software and
carries a contact address for the instance that sent the request:

```
scanprivacy/0.1 (+passive EU privacy conformance observation; independent research, good faith; contact: ...)
```

Two things are true and worth stating plainly.

**You can stop it, and it will stay stopped.** The engine reads `robots.txt`
before every URL it requests, documents included, and a disallow is honoured
rather than noted. A rule for `scanprivacy` — or a blanket `User-Agent: *`
disallow — is enough; nothing needs to be negotiated with anybody.

**You can ask.** Write to the contact address in the User-Agent you received.
Whoever runs that instance is answerable for it. If it was this project's own
hosted instance, that address is `abuse@scanprivacy.org`, and a request to stop
does not need a reason.

The engine loads public pages with a headless browser and reads the legal
documents they link to. It does not submit forms, authenticate, enumerate,
fuzz, or repeat a request in order to provoke an error, and it makes at most one
page load per second per host.
