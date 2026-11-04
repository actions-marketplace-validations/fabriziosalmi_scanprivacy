# Runs the API (`scanprivacy serve`) or any CLI command. The image binds
# nothing to the network by itself: the default command listens on 0.0.0.0
# inside the container, which the engine refuses unless SCANPRIVACY_API_KEY is
# set, so a container started without a key fails at startup instead of
# serving strangers in the operator's name.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 libcairo2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE requirements.lock ./
COPY src ./src
RUN pip install --require-hashes --no-deps -r requirements.lock \
 && pip install --no-deps . \
 && python -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 scanprivacy \
 && mkdir -p /home/scanprivacy/data \
 && chown scanprivacy /home/scanprivacy/data
USER scanprivacy
WORKDIR /home/scanprivacy

# Results are written under ./data. Without a volume they live in the
# container's writable layer and go with it, while the API keeps telling
# callers a scan id is valid.
VOLUME /home/scanprivacy/data

EXPOSE 8099
ENTRYPOINT ["scanprivacy"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8099"]
