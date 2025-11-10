# Rekrypt Transform Service

Stateless proxy re-encryption transform service.

## Quick Start

```bash
make build
./rekrypt-transform
```

## API

**POST /api/transform**

```json
{
  "encrypted_value": "base64...",
  "transform_key": "base64...",
  "signing_keypair": "base64..."
}
```

Returns:
```json
{
  "transformed_value": "base64..."
}
```

**GET /health**

```json
{ "status": "ok", "time": 1762769530 }
```

## Build

```bash
# From project root
make build-server

# Local
CGO_ENABLED=1 go build -o rekrypt-transform
```

## Docker

```bash
docker build -t rekrypt-transform .
docker run -p 8080:8080 rekrypt-transform
```

## License

AGPL-3.0-or-later
