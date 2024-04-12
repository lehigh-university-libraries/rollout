FROM golang:1.22-bookworm

WORKDIR /app

COPY . ./

RUN apt-get update \
  && apt-get install -y docker.io curl git jq \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && go mod download \
  && go build -o /app/rollout \
  && go clean -cache -modcache

ENTRYPOINT [ "/app/rollout"]
