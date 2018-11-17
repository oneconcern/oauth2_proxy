FROM golang:alpine as builder

RUN mkdir -p /stage/data /stage/etc/ssl/certs &&\
  apk add --no-cache musl-dev gcc ca-certificates mailcap upx tzdata zip git &&\
  update-ca-certificates &&\
  cp /etc/ssl/certs/ca-certificates.crt /stage/etc/ssl/certs/ca-certificates.crt &&\
  cp /etc/mime.types /stage/etc/mime.types

WORKDIR /usr/share/zoneinfo
RUN zip -r -0 /stage/zoneinfo.zip .

RUN mkdir -p /.cache && chown 1000 /.cache

WORKDIR /

ADD . /go/src/github.com/bitly/oauth2_proxy
WORKDIR /go/src/github.com/bitly/oauth2_proxy

RUN go get -d ./... 
RUN go build -o /stage/oauth2_proxy --ldflags '-s -w -linkmode external -extldflags "-static"' .
RUN upx /stage/oauth2_proxy

# Build the dist image
FROM scratch
COPY --from=builder /stage /
ENV ZONEINFO /zoneinfo.zip
ENTRYPOINT ["/oauth2_proxy"]
