
DOCKER := $(shell which docker)
DOCKER_TAG := arablocks/ann

docker: Dockerfile
	$(DOCKER) build -t $(DOCKER_TAG) .
