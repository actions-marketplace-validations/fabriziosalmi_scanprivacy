# Runs the API (`scanprivacy serve`) or any CLI command. The image binds
# nothing to the network by itself: the default command listens on 0.0.0.0
# inside the container, which the engine refuses unless SCANPRIVACY_API_KEY is
# set, so a container started without a key fails at startup instead of
# serving strangers in the operator's name.
# Pinned by digest: a tag moves, and this image runs a browser against other
# people's sites. Dependabot proposes the next digest.
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

# Which commit this image was built from, so a running instance can be tied to
# source (AGPL section 13 asks for exactly that). Passed by the build:
#   docker build --build-arg REVISION=$(git rev-parse HEAD) --build-arg VERSION=0.1.0 .
ARG REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.title="scanprivacy" \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/scanprivacy" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# hadolint ignore=DL3008
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 libcairo2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE requirements.runtime.lock ./
COPY src ./src
RUN pip install --require-hashes --no-deps -r requirements.runtime.lock \
 && pip install --no-deps . \
 && python -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 scanprivacy \
 && mkdir -p /data \
 && chown scanprivacy /data
USER scanprivacy
WORKDIR /home/scanprivacy

# Results are written under SCANPRIVACY_DATA_DIR. Without a volume they live in
# the container's writable layer and go with it, while the API keeps telling
# callers a scan id is valid.
ENV SCANPRIVACY_DATA_DIR=/data
VOLUME /data

EXPOSE 8099

# `/healthz` answers 503 when results cannot be stored. A container that runs a
# one-off CLI command is not a server, so the check only means something for the
# default command.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=3)"
ENTRYPOINT ["scanprivacy"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8099"]
