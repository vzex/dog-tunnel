
all: 
	@make release
release:
	make client
debug:
	make client_debug
client_debug:
	@go build -gcflags "-N -l" -o dtunnel_d client.go
client:
	@go build -ldflags "-s -w" -o dtunnel client.go
clean:
	@rm -rf dtunnel dtunnel_d dtunnel_s_d dtunnel_s
.PHONY: all debug release client_debug server_debug client server clean
