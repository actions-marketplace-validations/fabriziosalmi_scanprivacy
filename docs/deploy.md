# Deployment

```bash
docker build -t scanprivacy .
docker run --rm -e SCANPRIVACY_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -e SCANPRIVACY_CONTACT=you@example.org -p 127.0.0.1:8099:8099 \
  -v scanprivacy-data:/data scanprivacy
```

Without `SCANPRIVACY_API_KEY` the server refuses to start on a non-loopback bind, and the image's default command binds to all interfaces inside the container, so a container started without a key exits instead of serving.

## Network policy

The service refuses to connect to private addresses by itself (an egress proxy that checks every connection, see the README), but that is a second line. The first should be the network: deny the container's egress to loopback, link-local (the cloud metadata service), private and CGNAT ranges, and allow only what a scan needs (public DNS and ports 80/443). With Docker on Linux, a rule in the `DOCKER-USER` chain does it; on a cloud host, a security group or egress firewall.

The check cannot see WebRTC or other UDP paths a page might try to open; the network rule is what covers them.

## Where results live

Every finished scan is written to `/data/scans/<id>.json` (the image sets `SCANPRIVACY_DATA_DIR=/data`; outside the image the default is `data/` in the working directory), and a scan id stays valid after a restart because the API reads it back from there. Mount a volume on that directory, as above, or the results go with the container. `/healthz` answers 503 when that directory is not writable.

## Before you expose it

The engine makes requests to third-party sites with a User-Agent naming you and your contact address (`SCANPRIVACY_CONTACT`). An instance open to strangers sends those requests in your name. Put authentication in front, keep the container off your internal network, and read "Running the API anywhere but loopback" and "Scope: legitimate requests only" in the README.

If you run a modified build as a service, set `SCANPRIVACY_SOURCE_URL` to your own source (AGPL section 13).

## Single process

The scan queue, the concurrency ceiling and the per-host rate limit live in the memory of one process. Run one instance per data volume; do not put several replicas behind a load balancer and expect the limits to hold between them (a scan id would also be found only by the replica that holds it, or by any replica sharing the volume). Tune with `SCANPRIVACY_MAX_CONCURRENT_SCANS`, `SCANPRIVACY_MAX_SCANS_IN_FLIGHT`, `SCANPRIVACY_SCAN_RETENTION`; logging with `SCANPRIVACY_LOG_LEVEL` (default INFO, to stderr).

## Upgrading and rolling back

Stored scans are plain JSON with a `schema_version` (currently 1; files written before it existed are read as 1). To upgrade, run the new image on the same data volume: every stored scan stays readable. To roll back, run the older image on the same volume. If the older build meets a file with a newer `schema_version` it refuses it with an explicit error (HTTP 500 on `/v1/scans/<id>`, `stored result is unreadable`) rather than misreading it, and everything written by the older build keeps working.

The evidence and findings digests do not depend on the engine version, so `scanprivacy verify` keeps passing across upgrades. The ruleset digest changes when a rule does; that is what it is for.

## Which build is this

The image carries its commit and version as OCI labels (`docker inspect --format '{{json .Config.Labels}}' scanprivacy`), set by the build arguments `REVISION` and `VERSION`. A modified build run as a service should also set `SCANPRIVACY_SOURCE_URL` (AGPL section 13).
