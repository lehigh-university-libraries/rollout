#!/usr/bin/env bash

set -eou pipefail

echo "Triggering rollout via $ROLLOUT_URL"
echo "${ID_TOKEN_1}" | jq -rR 'split(".") | .[1] | @base64d | fromjson | .project_path + " " + .user_email + " " + .aud'

for i in $(seq 1 3); do
  STATUS=$(curl -s \
    --max-time 900 \
    -w '%{http_code}' \
    -o /dev/null  \
    -d '{"git-branch": "'"${CI_COMMIT_BRANCH}"'"}' \
    -H "Authorization: bearer ${ID_TOKEN_1}" \
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
