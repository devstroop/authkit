# syntax=docker/dockerfile:1
FROM rust:1.98-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p authkit-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/authkit-server /usr/local/bin/authkit-server
ENV AUTHKIT_ENV=production
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/authkit-server", "doctor"] || exit 1
ENTRYPOINT ["/usr/local/bin/authkit-server"]
CMD ["serve"]
