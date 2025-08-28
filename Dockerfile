FROM golang:1.25-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a

WORKDIR /app

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG \
  # renovate: datasource=repology depName=debian_12/ca-certificates
  CA_CERTIFICATES_VERSION="20230311" \
  # renovate: datasource=repology depName=debian_12/curl
  CURL_VERSION="7.88.1-10+deb12u12" \
  # renovate: datasource=repology depName=debian_12/sudo
  SUDO_VERSION="1.9.13p3-1+deb12u1" \
  # renovate: datasource=repology depName=debian_12/jq
  JQ_VERSION="1.6-2.1" \
  # renovate: datasource=repology depName=debian_12/git
  GIT_VERSION="1:2.39.5-0+deb12u2" \
  ## renovate: datasource=repology depName=debian_12/docker-ce
  DOCKER_VERSION="5:27.4.0-1~debian.12~bookworm" \
  ## renovate: datasource=repology depName=debian_12/docker-ce-cli
  DOCKER_CLI_VERSION="5:27.4.0-1~debian.12~bookworm" \
  ## renovate: datasource=repology depName=debian_12/containerd.io
  CONTAINERD_VERSION="1.7.24-1" \
  ## renovate: datasource=repology depName=debian_12/docker-buildx-plugin
  DOCKER_BUILDX_VERSION="0.19.2-1~debian.12~bookworm" \
  ## renovate: datasource=repology depName=debian_12/docker-compose-plugin
  DOCKER_COMPOSE_VERSION="2.31.0-1~debian.12~bookworm"

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
