FROM golang:1.25-trixie@sha256:a733d0a3a4c2349114bfaa61b2f41bfd611d5dc4a95d0d12c485ff385bd285b3

WORKDIR /app

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG \
  # renovate: datasource=repology depName=debian_13/ca-certificates
  CA_CERTIFICATES_VERSION="20250419" \
  # renovate: datasource=repology depName=debian_13/curl
  CURL_VERSION="8.14.1-2" \
  # renovate: datasource=repology depName=debian_13/sudo
  SUDO_VERSION="1.9.16p2-3" \
  # renovate: datasource=repology depName=debian_13/jq
  JQ_VERSION="1.7.1-6+deb13u1" \
  # renovate: datasource=repology depName=debian_13/git
  GIT_VERSION="1:2.47.2-0.2" \
  # renovate: datasource=repology depName=debian_13/docker-ce
  DOCKER_VERSION="5:28.3.3-1~debian.13~trixie" \
  # renovate: datasource=repology depName=debian_13/docker-ce-cli
  DOCKER_CLI_VERSION="5:28.3.3-1~debian.13~trixie" \
  # renovate: datasource=repology depName=debian_13/containerd.io
  CONTAINERD_VERSION="1.7.27-1" \
  # renovate: datasource=repology depName=debian_13/docker-buildx-plugin
  DOCKER_BUILDX_VERSION="0.26.1-1~debian.13~trixie" \
  # renovate: datasource=repology depName=debian_13/docker-compose-plugin
  DOCKER_COMPOSE_VERSION="2.39.1-1~debian.13~trixie"

# hadolint ignore=SC1091
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl="${CURL_VERSION}" \
      git="${GIT_VERSION}" \
      jq="${JQ_VERSION}" \
      sudo="${SUDO_VERSION}" \
      ca-certificates="${CA_CERTIFICATES_VERSION}" && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      docker-ce="${DOCKER_VERSION}" \
      docker-ce-cli="${DOCKER_CLI_VERSION}" \
      containerd.io="${CONTAINERD_VERSION}" \
      docker-buildx-plugin="${DOCKER_BUILDX_VERSION}" \
      docker-compose-plugin="${DOCKER_COMPOSE_VERSION}" && \
   apt-get clean && \
   rm -rf /var/lib/apt/lists/*

COPY . ./

RUN go mod download && \
   go build -o /app/rollout && \
   go clean -cache -modcache

HEALTHCHECK CMD curl -s http://localhost:8080/healthcheck | grep -q ok

ENTRYPOINT [ "/app/rollout"]
