# pcap-har-watcher
Watch a given folder for new pcap files and transform them into HAR files with a series of additional changes in order to enrich the files to be
afterwards fed into an ELK instance (Elasticsearch, Logstash, Kibana).
This pcap files are originally meant to come from observing docker containers run in a network, so additional information about them will be
included in pcap file naming scheme.

  * Decode the base64 strings into JSON objects.
  * Add additional container information into the HAR file to allow the tracing of http responses accross the docker network.

## Usage

```sh
$ ./pcap-har-watcher.py -i <input_folder> -o <output_folder> -p <period> -dc <docker-compose_file>
```

  * -i <input_folder>: the folder where all the .pcap files are being periodically stored.
  * -o <output_folder>: the folder where the transformed .pcap into .har files are stored. This folder will replicate the same structure as the **input_folder**.
  * -p <period>: the amount of time in seconds the script will look for new pcap files for transformation.
  * -dc <docker_compose_file>: the docker compose file to extract information about the containers links.

## Example

```sh
$ ./pcap-har-watcher.py -i ../docker-watcher/pcap/ -o output/ -p 6 -dc docker-compose.yml
```


## Acknowledgments

This script uses the **pcap2har** script found [here](https://github.com/andrewf/pcap2har) slighly modified for it's purposes.

Copyright for the **pcap2har** project:

Copyright (c) 2009 Andrew Fleenor, Ryan C. Witt, Jake Holland, and Google, Inc.
All rights reserved.
