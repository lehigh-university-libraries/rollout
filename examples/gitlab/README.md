# GitLab rollout example

In this example, you can find the [.gitlab-ci.yml](./.gitlab-ci.yml) you could add to your repo, along with [a bash script](./trigger-rollout.sh) that calls the rollout service deployed in your environment(s).

The GitLab CI deploys to a dev/stage/prod environment, and has exponential backoff on the deploy.

See https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html for more information on the `id_tokens` YML spec.
