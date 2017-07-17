#!/bin/bash

docker run --rm -it \
           --network apphttplogger_default \
           --link apphttplogger_elasticsearch_1:elasticsearch \
           -v "$PWD"/src:/app/src/ \
           -v "$PWD"/pcap:/app/pcap \
	   -v "$PWD"/containers:/app/containers \
           -v "$PWD"/har:/app/har \
           -v "$PWD"/docker-compose.yml:/app/docker-compose.yml \
           --name mu-har-transformation-service \
           mu-har-transformation-service
