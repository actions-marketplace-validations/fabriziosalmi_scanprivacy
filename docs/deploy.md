# Deployment

```bash
docker build -t scanprivacy .
docker run --rm -e SCANPRIVACY_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -e SCANPRIVACY_CONTACT=you@example.org -p 127.0.0.1:8099:8099 \
  -v scanprivacy-data:/home/scanprivacy/data scanprivacy
```

Without `SCANPRIVACY_API_KEY` the server refuses to start on a non-loopback bind, and the image's default command binds to all interfaces inside the container, so a container started without a key exits instead of serving.

## Network policy

The service refuses to connect to private addresses by itself (an egress proxy that checks every connection, see the README), but that is a second line. The first should be the network: deny the container's egress to loopback, link-local (the cloud metadata service), private and CGNAT ranges, and allow only what a scan needs (public DNS and ports 80/443). With Docker on Linux, a rule in the `DOCKER-USER` chain does it; on a cloud host, a security group or egress firewall.

The check cannot see WebRTC or other UDP paths a page might try to open; the network rule is what covers them.

## Where results live

Every finished scan is written to `/home/scanprivacy/data/scans/<id>.json`, and a scan id stays valid after a restart because the API reads it back from there. Mount a volume on that directory, as above, or the results go with the container. `/healthz` answers 503 when that directory is not writable.

## Before you expose it

The engine makes requests to third-party sites with a User-Agent naming you and your contact address (`SCANPRIVACY_CONTACT`). An instance open to strangers sends those requests in your name. Put authentication in front, keep the container off your internal network, and read "Running the API anywhere but loopback" and "Scope: legitimate requests only" in the README.

If you run a modified build as a service, set `SCANPRIVACY_SOURCE_URL` to your own source (AGPL section 13).
