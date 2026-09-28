FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p endpoint-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/endpoint-server /usr/local/bin/endpoint-server
ENTRYPOINT ["/usr/local/bin/endpoint-server"]
CMD ["serve"]
