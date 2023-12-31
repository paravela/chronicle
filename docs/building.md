# Building Chronicle

BTP maintains and distributes a docker image for the
[Chronicle transaction processor](./chronicle_architecture.md#transaction-processor).
End users of Chronicle need to build their own versions to support
their custom domains. BTP also maintains and distributes a Docker build
image to be used in CI/CD.

## Example Dockerfile

Assuming a valid [Chronicle domain configuration](./domain_modeling.md) located
in the same directory as the Dockerfile, the following will build a
domain-specific Chronicle. You should only need to source control the Dockerfile
and domain.yaml - Chronicle's build image will do the rest.

```docker
FROM blockchaintp/builder:{VERSION_NUMBER} as domain

COPY domain.yaml chronicle-domain/
cargo build --release --frozen --bin chronicle
```

## In-Memory Version

For rapid development and testing purposes, a standalone version of Chronicle
can be built and distributed as a docker image or binary. See the
[configuration guide](./config.md) for more detail.

```docker
FROM blockchaintp/builder:{VERSION_NUMBER} as domain

COPY domain.yaml chronicle-domain/
cargo build --release --frozen --features inmem --bin chronicle
```
