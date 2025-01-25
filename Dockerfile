FROM golang:1.23-bookworm@sha256:3149bc5043fa58cf127fd8db1fdd4e533b6aed5a40d663d4f4ae43d20386665f

ENV PORT=8080

WORKDIR /app

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=SC1091
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl=7.88.1-10+deb12u8 \
      git=1:2.39.5-0+deb12u1 \
      jq=1.6-2.1 \
      sudo=1.9.13p3-1+deb12u1 \
      ca-certificates=20230311 && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      docker-ce=5:27.4.0-1~debian.12~bookworm \
      docker-ce-cli=5:27.4.0-1~debian.12~bookworm \
      containerd.io=1.7.24-1 \
      docker-buildx-plugin=0.19.2-1~debian.12~bookworm \
      docker-compose-plugin=2.31.0-1~debian.12~bookworm && \
   apt-get clean && \
   rm -rf /var/lib/apt/lists/*

COPY . ./

RUN go mod download && \
   go build -o /app/rollout && \
   go clean -cache -modcache

HEALTHCHECK CMD curl -s http://localhost:${PORT}/healthcheck | grep -q ok

ENTRYPOINT [ "/app/rollout"]
