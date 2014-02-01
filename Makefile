
all: 
	@make release
release:
	make client
	make server
debug:
	make client_debug
	make server_debug
client_debug:
	@go build -gcflags "-N -l" -o dtunnel_d client.go
server_debug:
	@go build -gcflags "-N -l" -o dtunnel_s_d server.go
client:
	@go build -ldflags "-s -w" -o dtunnel client.go
server:
	@go build -ldflags "-s -w" -o dtunnel_s server.go
clean:
	@rm -rf dtunnel dtunnel_d dtunnel_s_d dtunnel_s
.PHONY: all debug release client_debug server_debug client server clean
