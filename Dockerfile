# Base images are pinned by tag and digest, so every rebuild uses the same
# toolchain (rustc 1.99.0) and the same runtime. Update both together,
# deliberately.
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build

WORKDIR /src
ENV CARGO_BUILD_JOBS=2
COPY Cargo.toml Cargo.lock ./
COPY core/ core/
COPY server/ server/
COPY wasm-challenger/ wasm-challenger/
RUN rustup target add wasm32-unknown-unknown \
    && cargo build --locked --release -p compute-to-access-server \
    && cargo build --locked --release -p c2a-challenger --target wasm32-unknown-unknown \
    && RUSTFLAGS="-C target-feature=+simd128" cargo build --locked --release -p c2a-challenger \
        --target wasm32-unknown-unknown --target-dir target/wasm-simd

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 challenger \
    && useradd --uid 10001 --gid challenger --no-create-home --shell /usr/sbin/nologin challenger \
    && mkdir -p /opt/c2a/browser /var/lib/c2a \
    && chown -R challenger:challenger /var/lib/c2a

WORKDIR /opt/c2a
COPY --from=build --chown=10001:10001 /src/target/release/compute-to-access-server /usr/local/bin/compute-to-access-server
COPY --chown=10001:10001 browser/index.html browser/challenger.js browser/controller.js /opt/c2a/browser/
COPY --from=build --chown=10001:10001 /src/target/wasm32-unknown-unknown/release/c2a_challenger.wasm /opt/c2a/browser/wasm-challenger.wasm
COPY --from=build --chown=10001:10001 /src/target/wasm-simd/wasm32-unknown-unknown/release/c2a_challenger.wasm /opt/c2a/browser/wasm-challenger-simd.wasm

USER 10001:10001
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/compute-to-access-server"]
