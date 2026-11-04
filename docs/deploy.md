# Deployment

```bash
docker build -t scanprivacy .
docker run --rm -e SCANPRIVACY_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -e SCANPRIVACY_CONTACT=you@example.org -p 127.0.0.1:8099:8099 scanprivacy
```

Without `SCANPRIVACY_API_KEY` the server refuses to start on a non-loopback bind, and the image's default command binds to all interfaces inside the container, so a container started without a key exits instead of serving.

## Before you expose it

The engine makes requests to third-party sites with a User-Agent naming you and your contact address (`SCANPRIVACY_CONTACT`). An instance open to strangers sends those requests in your name. Put authentication in front, keep the container off your internal network, and read "Running the API anywhere but loopback" and "Scope: legitimate requests only" in the README.

If you run a modified build as a service, set `SCANPRIVACY_SOURCE_URL` to your own source (AGPL section 13).
