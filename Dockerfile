FROM docker.io/golang:1.23-alpine AS builder

LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <aescanero@disasterproject.com>"

USER 0

RUN apk --no-cache add ca-certificates git && mkdir /app

WORKDIR /app/
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o api .

#######################
FROM docker.io/debian:stable-slim AS server

LABEL org.opencontainers.image.authors="Alejandro Escanero Blanco <aescanero@disasterproject.com>"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        gettext-base ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/ldap-api /.
RUN chmod +x /ldap-api

USER 1001

WORKDIR /

EXPOSE 8080

ENV LDAP_HOST=localhost \
    LDAP_PORT=389 \
    LDAP_BIND_DN="" \
    LDAP_BIND_PASS="" \
    LDAP_BASE_DN="dc=example,dc=com" \
    LDAP_USE_SSL=false

ENTRYPOINT ["/ldap-api"]
CMD ["start"]
