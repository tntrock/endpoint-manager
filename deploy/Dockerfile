FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p endpoint-server
# 派送套件目錄：distroless 沒有 shell，先在建置階段建立，再以 nonroot 擁有者複製過去
RUN mkdir -p /packages

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/endpoint-server /usr/local/bin/endpoint-server
COPY --from=build --chown=65532:65532 /packages /packages
ENTRYPOINT ["/usr/local/bin/endpoint-server"]
CMD ["serve"]
