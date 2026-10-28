# Сборка
# Версия должна быть не ниже директивы go в go.mod, иначе Go попытается скачать toolchain.
FROM golang:1.27.3-alpine AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src

# Сначала только зависимости: этот слой кэшируется, пока не меняются go.mod/go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# Запуск
# distroless: только бинарник, без shell и пакетного менеджера; пользователь nonroot.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
EXPOSE 8443
ENTRYPOINT ["/server"]