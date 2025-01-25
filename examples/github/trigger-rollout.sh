#!/usr/bin/env bash

set -eou pipefail

echo "Fetching GitHub OIDC token"
TOKEN=$(curl -s \
    -H "Accept: application/json; api-version=2.0" \
    -H "Content-Type: application/json" -d "{}"  \
    -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -er '.value')

# add some buffer to avoid iat issues
sleep 5

echo "Triggering rollout via $ROLLOUT_URL"
echo "${TOKEN}" | jq -rR 'split(".") | .[1] | @base64d | fromjson | .aud'

for i in {1..3}; do
  STATUS=$(curl -s \
    --max-time 900 \
    -w '%{http_code}' \
    -o /dev/null  \
    -d '{"git-branch": "'"${GITHUB_REF_NAME}"'"}' \
    -H "Authorization: Bearer ${TOKEN}" \
    "${ROLLOUT_URL}")

  echo "Received $STATUS"
  if [ "${STATUS}" = 200 ]; then
    echo "Rollout complete"
    exit 0
  fi

  SLEEP_INTERVAL=$(( 60 * i ))
  echo "trying again in ${SLEEP_INTERVAL}s"
  sleep "${SLEEP_INTERVAL}"
done

echo "Rollout failed. Check logs"
exit 1
