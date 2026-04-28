# audio-proxy

HTTP/HTTPS proxy app written with Tokio and hyper.

- HTTPS uses a hand-written `CONNECT host:port` tunnel.
- Plain HTTP requests are parsed and forwarded by hyper.
- Only these hosts, plus their subdomains, are allowed by default:
  - `tidal.com`
  - `airable.io`
  - `qobuz.com`
  - `spotifycdn.com`

## Run

```sh
cargo run -- --listen 127.0.0.1:8080
```

Use it from a standard HTTP proxy client:

```sh
curl -x http://127.0.0.1:8080 http://tidal.com/
curl -x http://127.0.0.1:8080 https://tidal.com/
```

Override the allowlist with repeated `--allow-domain` flags:

```sh
cargo run -- --listen 0.0.0.0:8080 \
  --allow-domain tidal.com \
  --allow-domain qobuz.com
```

Targets outside the allowlist return `403 Forbidden`.
