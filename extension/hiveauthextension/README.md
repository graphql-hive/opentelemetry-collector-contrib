# Hive Authentication Extension

This extension provides authentication for GraphQL Hive services. It implements both HTTP and gRPC authentication using Hive API tokens.

## Configuration

The extension supports the following configuration options:

- `api_token` (required): The API token for Hive authentication
- `endpoint` (required): The Hive GraphQL endpoint URL

### Example Configuration

```yaml
extensions:
  hiveauth:
    api_token: "your-hive-api-token"
    endpoint: "https://app.graphql-hive.com/graphql"

processors:
  batch:

exporters:
  logging:
    loglevel: debug
  otlphttp:
    endpoint: "https://app.graphql-hive.com/usage"
    auth:
      authenticator: hiveauth

service:
  extensions: [hiveauth]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, otlphttp]
```

## Usage

The extension can be used as an authenticator for HTTP and gRPC exporters that need to communicate with Hive services. It automatically adds the appropriate authorization headers with the configured API token.

## Security

- API tokens are handled as opaque strings to prevent accidental logging
- Uses constant-time comparison for token validation to prevent timing attacks
- Always requires transport security for gRPC connections