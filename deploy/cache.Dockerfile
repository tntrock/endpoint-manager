FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p endpoint-cache
# 資料目錄：distroless 沒有 shell，先在建置階段建立，再以 nonroot 擁有者（0700）複製過去
RUN mkdir -m 0700 /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/endpoint-cache /usr/local/bin/endpoint-cache
COPY --from=build --chown=65532:65532 /data /data
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/endpoint-cache"]
CMD ["run", "--data-dir", "/data"]
