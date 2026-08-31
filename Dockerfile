FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/jwtdemo .

FROM alpine:3.20
LABEL maintainer="Stephan Zerhusen <strephan.zerhusen@gmail.com>"

COPY --from=build /out/jwtdemo /usr/share/jwt-spring-security-demo

EXPOSE 8080
ENTRYPOINT ["/usr/share/jwt-spring-security-demo"]
