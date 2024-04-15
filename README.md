# rollout

Trigger a deployment of your application from a CI/CD pipeline to an instance of your application running on a VM.

```
$ curl -s -H "Authorization: bearer abc..." https://example.com/your/rollout/path
Rollout complete
```

## Purpose

Instead of managing SSH keys in your CI/CD that has access to your production environment to run deployment scripts, this serivce can be running in your production environment to handle deploying code changes.

Requires creating a JWT from your CI provider, and sending that token to this service running in your deployment environment to trigger the deployment script.

Also requires a `rollout.sh` script that can handle all the command needing ran to rollout your software.

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

## OIDC Provider examples

This service requires two envionrment variables.

- `JWKS_URI` - the URL of the OIDC Provider's [JSON Web Key (JWK) set document](https://www.rfc-editor.org/info/rfc7517). This is used to ensure the JWT was signed by the provider.
- `JWT_AUD` - the audience set in the JWT token.

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
- [ ] Allow more custom auth handling
- [ ] Allow more custom rollout than a single bash script
