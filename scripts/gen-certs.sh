#!/bin/sh
# Генерирует самоподписанный TLS-сертификат для локального запуска (localhost).
# Использование: sh scripts/gen-certs.sh [каталог]   (по умолчанию ./certs)
set -eu

DIR="${1:-certs}"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -keyout "$DIR/server.key" -out "$DIR/server.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Сервер в контейнере работает от пользователя nonroot и должен прочитать оба файла.
chmod 644 "$DIR/server.key" "$DIR/server.crt"
echo "Создано: $DIR/server.crt, $DIR/server.key"
