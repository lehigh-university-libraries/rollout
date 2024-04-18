# rollout

Deploy your application from a CI/CD pipeline via `cURL` + JWT auth.

```
$ curl -s -d '{"git-branch": "main"}' -H "Authorization: bearer abc..." https://example.com/your/rollout/path
Rollout complete
```

## Purpose

Instead of managing SSH keys in your CI/CD for accounts that have privileged access to perform deployments in your production environment, this service can handle deploying code changes.

Requires creating a JWT from your CI provider, and sending that token to this service running in your deployment environment to trigger a deployment script.

Also requires a `rollout.sh` script that can handle all the commands needing ran to rollout your software.

## Install

```
$ docker build -t rollout:latest
$ docker run \
  --env JWKS_URI=$JWKS_URI \
  --env JWT_AUD=$JWT_AUD \
  -v /path/to/rollout.sh:/rollout.sh \
  -p 8080:8080 \
  rollout:latest
```

You should then proxy that port with some service that can handle TLS for you.

## OIDC Provider examples

This service requires two environment variables.

- `JWKS_URI` - the URL of the OIDC Provider's [JSON Web Key (JWK) set document](https://www.rfc-editor.org/info/rfc7517). This is used to ensure the JWT was signed by the provider.
- `JWT_AUD` - the audience set in the JWT token.
- `CUSTOM_CLAIMS` - (optional) JSON of key/value pairs to validate in the JWT e.g.
```
{"foo": "bar", "foo2": "bar2"}
```
- `ROLLOUT_CMD` (default: `/bin/bash`) - the command to execute a rollout
- `ROLLOUT_ARGS` (default: `/rollout.sh` ) - the args to pass to `ROLLOUT_CMD`

## Dynamic environment variables for ROLLOUT_CMD

There are a few environment variables you can make available to your rollout command.

These environment variables can be passed to the cURL command when rolling out your changes.

For example, if you want your rollout script to have the git repo and branch that is being deployed you can pass that in the rollout cURL call as seen below. Doing so will make an environment variable `$GIT_REPO` and `$GIT_BRANCH` available in your rollout script.

```
$ curl -s \
  -H "Authorization: bearer abc..." \
  -d '{"git-repo": "git@github.com:lehigh-university-libraries/rollout.git", "git-branch": "main"}' \
  https://example.com/your/rollout/path
```

These are the environment variables currently supported, keyed by their respective JSON key name:

| JSON Key       | Env Var Name  | Example JSON to send                 |
|----------------|---------------| -------------------------------------
| `docker-image` | `DOCKER_IMAGE`| `{"docker-image": "foo/bar:latest"}` |
| `docker-tag`   | `DOCKER_TAG`  | `{"docker-tag": "latest"}`           |
| `git-repo`     | `GIT_REPO`    | `{"git-repo": "foo/bar:latest"}`         |
| `git-branch`   | `GIT_BRANCH`  | `{"git-branch": "main"}`             |
| `rollout-arg1` | `ROLLOUT_ARG1`| `{"rollout-arg1": "FOO"}`            |
| `rollout-arg2` | `ROLLOUT_ARG2`| `{"rollout-arg2": "BAR"}`            |
| `rollout-arg3` | `ROLLOUT_ARG3`| `{"rollout-arg3": "BAZ"}`            |

If there is key/env var name that is generic enough that it warrants its own placeholder, it can be added by submitting an issue or a PR. Otherwise, use the general ARG variables.

### GitHub

```
JWKS_URI=https://token.actions.githubusercontent.com/.well-known/jwks
JWT_AUD=https://github.com/lehigh-university-libraries
```

### GitLab

```
JWKS_URI=https://gitlab.com/oauth/discovery/keys
JWT_AUD=aud-string-you-set-in-your-job
```

## TODO

- [ ] Add a full example for GitLab
- [ ] Add a full example for GitHub
- [ ] Install instructions using binary
- [ ] Tag/push versions to dockerhub
