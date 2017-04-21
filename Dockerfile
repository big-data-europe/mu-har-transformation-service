FROM python:2.7
MAINTAINER esteban.sastre@tenforce.com

ENV ELASTIC_HOST "http://localhost"
ENV ELASTIC_PORT "9200"
ENV PCAP_READ_DIR "pcap/"
ENV HAR_OUTPUT_DIR "har/"
ENV DOCKER_COMPOSE_PATH "docker-compose.yml"
ENV SLEEP_PERIOD '2'

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi

COPY . /app

CMD ["python", "pcap-har-watcher.py"]
