#!/bin/sh
# Generate one private Caido CA for this deployment; the backend receives only ca.crt.
set -eu
private=/caido-ca-private
public=/caido-ca-public
if [ -s "$private/ca.p12" ] && [ -s "$public/ca.crt" ]; then
    exit 0
fi
umask 077
tmp="$private/.new-$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' 0
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.key"
openssl req -x509 -new -key "$tmp/ca.key" -out "$tmp/ca.crt" \
    -days 3650 -subj "/O=Judah Security/CN=Prowl Assessment CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign"
openssl pkcs12 -export -inkey "$tmp/ca.key" -in "$tmp/ca.crt" \
    -out "$tmp/ca.p12" -passout pass: -name "Prowl Assessment CA"
install -m 0600 "$tmp/ca.p12" "$private/ca.p12"
install -m 0644 "$tmp/ca.crt" "$public/ca.crt"
chown 996:996 "$private/ca.p12"
