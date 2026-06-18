NETWORK ?= thinkmay_default

ARGS := $(filter-out fwd,$(MAKECMDGOALS))
SVC  := $(word 1,$(ARGS))
PORT := $(word 2,$(ARGS))

# make fwd <service> <port>   temporary port-forward, Ctrl-C to stop
.PHONY: fwd
fwd:
	docker run --rm -it --network $(NETWORK) -p $(PORT):$(PORT) \
		alpine/socat TCP-LISTEN:$(PORT),fork,reuseaddr TCP:$(SVC):$(PORT)

%:
	@:
