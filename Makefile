
all: 
	@make release
release:
	make client
debug:
	make client_debug
client_debug:
	@go build -gcflags "-N -l" -o dtunnel_lite_d client.go
client:
	@go build -ldflags "-s -w" -o dtunnel_lite client.go
clean:
	@rm -rf dtunnel_lite dtunnel_lite_d dtunnel_lite_s_d dtunnel_lite_s
.PHONY: all debug release client_debug server_debug client server clean
