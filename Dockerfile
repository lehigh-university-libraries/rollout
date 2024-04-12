FROM golang:1.22-bookworm

WORKDIR /app

RUN apt-get update \
  && apt-get install -y curl git jq sudo ca-certificates \
  && install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
  && chmod a+r /etc/apt/keyrings/docker.asc \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
  && apt-get update \
  && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY . ./

RUN go mod download \
  && go build -o /app/rollout \
  && go clean -cache -modcache

ENTRYPOINT [ "/app/rollout"]
