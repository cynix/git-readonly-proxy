# Introduction

This proxy provides read-only Git access over HTTP by denying git-receive-pack requests.

# Usage

By default, the proxy listens on 0.0.0.0:8080. Use the `-listen [host]:port` argument
to specify a different listening port.

# Certificates

The proxy needs to filter HTTPS traffic and therefore needs to supply TLS certificates
for the requested domain that is trusted by the client. It can issue certificates on
demand using a CA certificate, or load pre-generated certificates from file.

## Using a CA certificate

Specify the paths to the CA certificate and private key using `-ca-cert` and `-ca-key`.
The private key must not be password protected. The CA certificate should be trusted
by the client.

## Loading pre-generated certificates

Specify a directory that contains pre-generated server certificates and private keys
with `-certs-dir`. Each server's certificate/key should be located inside a directory
with the corresponding domain name, e.g. `${certs-dir}/example.com/cert.pem` and
`${certs-dir}/example.com/key.pem`.
