#!/bin/sh
# Генерирует самоподписанный TLS-сертификат для локального запуска (localhost).
# Использование: ./scripts/gen-certs.sh [каталог]   (по умолчанию ./certs)
set -eu

DIR="${1:-certs}"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -keyout "$DIR/server.key" -out "$DIR/server.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/server.key"
echo "Создано: $DIR/server.crt, $DIR/server.key"