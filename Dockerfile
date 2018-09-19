FROM golang:1.11-alpine as builder

RUN apk add git gcc g++

ADD . /app
WORKDIR /app

RUN GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/linux/dtunnel_s server.go

FROM alpine
RUN apk add -U tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime
COPY --from=builder /app/bin/linux/dtunnel_s /dtunnel_s
CMD [ "/dtunnel_s" ]

EXPOSE 8000
EXPOSE 8018/udp
