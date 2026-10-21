# stac-poc-policy
Repo to store test rego bundles for polling in services.

## Tests

Unit tests:

```
opa test policies/
```

End-to-end tests run the policies with pgstac, stac-fastapi-pgstac, stac-auth-proxy and a mock OIDC provider in Docker:

```
docker compose -f e2e/compose.yaml up -d --build
python3 e2e/scenarios.py
docker compose -f e2e/compose.yaml down -v
```
