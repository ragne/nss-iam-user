FROM amazonlinux:latest

# Adapted from https://github.com/rust-lang/docker-rust

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.34.2

RUN set -eux; \
    yum install -y git gcc gcc-c++ openssl-devel.x86_64; \
    rustArch='x86_64-unknown-linux-gnu'; rustupSha256='31c0581e3af128f7374d8439068475d11be60ce7b2301684a4cab81a39c76cb6' ; \
    url="https://static.rust-lang.org/rustup/archive/1.18.2/${rustArch}/rustup-init"; \
    curl -sS -o rustup-init "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain $RUST_VERSION; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;