# Example CI/CD

In this directory is [a docker-compose template](./docker-compose.yml) that would be deployed into your environment(s) to allow the CI/CD system to send requests to the rollout service.

## GitHub

In the [github](./github) directory you will find a sample GitHub Action script you could add to your GitHub repo to trigger deployments. You can see the script in action in [the GitHub Action integraton test that runs in this repo](../.github/workflows/github-integration-test.yml).

## GitLab

In the [gitlab](./gitlab) directory, you will find a sample `.gitlab-ci.yml` you could add to your GitLab repo to trigger deployments from self-hosted or gitlab.com
