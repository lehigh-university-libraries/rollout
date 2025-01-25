# Example CI/CD

In this directory is [a docker-compose template](./docker-compose.yml) that would be deployed into your environment(s) to allow the CI/CD system to send requests to the rollout service.

## GitHub

In the [github](../.github/workflows/github-integration-test.yml) you will find a sample GitHub Action you could add to your GitHub repo to trigger deployments.

## GitLab

In the [gitlab](./gitlab) directory, you will find a sample `.gitlab-ci.yml` you could add to your GitLab repo to trigger deployments from self-hosted or gitlab.com
