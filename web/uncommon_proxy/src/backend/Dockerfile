FROM rust@sha256:ff798ceb500fa43c91db10db881066057fefd36e16d531e7b1ed228ab2246175

WORKDIR /app

COPY ./ ./

RUN cargo build --release

EXPOSE 8081
CMD ["./target/release/backend"]