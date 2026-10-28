# threat-service

Сервис для обмена информацией об угрозах по MD5-хешу файла. Сделан по OpenAPI-спецификации
из `api/openapi.yaml`: код сервера и модели генерируются из неё через oapi-codegen,
по ней же валидируются входящие запросы.

Go, PostgreSQL, pgx, Docker.

## API

- `GET /info/{md5}` — получить запись
- `POST /info` — создать запись, MD5 должен быть уникальным
- `PUT /info/{md5}` — заменить запись целиком

Кроме обязательных `md5` и `name` у угрозы есть необязательные поля `severity` (low, medium, high, critical),
`sha256`, `file_size`, `first_seen`, `last_seen` и `description`. Поля `created_at` и `updated_at` выставляет сервер.
Ограничения на значения описаны в спецификации.

MD5 и SHA-256 принимаются в любом регистре, хранятся в нижнем. При PUT необязательные поля, которых нет в запросе, очищаются.

## Запуск

Нужны Docker и openssl.

```bash
sh scripts/gen-certs.sh
cp .env.example .env
docker compose up --build -d
```

Сервис будет доступен на `https://localhost:8443`, PostgreSQL на `localhost:5434`.
Сертификат самоподписанный, поэтому curl нужно указать его явно:

```bash
curl --cacert certs/server.crt -X POST https://localhost:8443/info \
  -H "X-API-Key: <ключ writer из .env>" -H "Content-Type: application/json" \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic"}'

curl --cacert certs/server.crt -H "X-API-Key: <ключ из .env>" \
  https://localhost:8443/info/d41d8cd98f00b204e9800998ecf8427e
```

Без Docker (нужен Go 1.27.3 или новее, база из compose):

```bash
docker compose up -d db
API_KEYS="dev-writer-0123456789:writer,dev-reader-0123456789:reader" \
TLS_CERT_FILE=certs/server.crt TLS_KEY_FILE=certs/server.key \
go run ./cmd/server
```

## Настройка

Через переменные окружения:

- `API_KEYS` — обязательная, список `ключ:роль` через запятую. Роль `reader` может только читать, `writer` может всё. Ключ не короче 16 символов.
- `DATABASE_URL` — по умолчанию `postgres://threat:threat@localhost:5434/threats?sslmode=disable`.
- `TLS_CERT_FILE`, `TLS_KEY_FILE` — сертификат и ключ в PEM. Задаются обе или ни одной, без них сервер работает по HTTP.
- `HTTP_ADDR` — по умолчанию `:8443` с TLS и `:8080` без него.

## Защита

Ключ передаётся в заголовке `X-API-Key`. Без ключа или с неверным ключом сервер отвечает 401, при нехватке прав 403.
С одного IP можно делать в среднем 10 запросов в секунду с всплеском до 20, сверх этого — 429.
TLS не ниже 1.2. Тело запроса ограничено 1 МБ, обработка запроса — 5 секундами.
Внутренние ошибки пишутся в лог, клиенту возвращается 500 без подробностей.

## Тесты

```bash
go test ./...
```

Интеграционные тесты в `internal/storage` работают с настоящим PostgreSQL и без переменной
`TEST_DATABASE_URL` пропускаются, при этом `go test` всё равно пишет `ok`. Чтобы их запустить:

```bash
docker compose up -d db
TEST_DATABASE_URL="postgres://threat:threat@localhost:5434/threats?sslmode=disable" \
  go test -race -count=1 ./...
```

Тесты создают временную схему и удаляют её после себя, данные в базе не трогают.

## Разработка

После изменения спецификации нужно перегенерировать код: `go generate ./...`.

Схема БД из `migrations/` применяется только при первом создании тома PostgreSQL.
Если схема изменилась, базу нужно пересоздать, данные при этом удалятся:

```bash
docker compose down -v
docker compose up -d
```

## Допущения

- Сервис принимает запросы напрямую, без прокси. Поэтому IP для rate-limit берётся из соединения, а заголовку `X-Forwarded-For` сервис не доверяет.
- Счётчики rate-limit хранятся в памяти, у каждого экземпляра сервиса свои.
- Соединение с базой внутри docker-сети идёт без TLS, пароль в `docker-compose.yml` тестовый.
- Есть только операции из спецификации, списка и удаления нет.
