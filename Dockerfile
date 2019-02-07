FROM ubuntu:18.04

RUN apt-get update && apt-get install -y python-pip rpm wget

COPY . /src

WORKDIR /src

RUN pip install -r requirements.txt

RUN  wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.6.0.rpm

RUN python ./fimgen.py -p elasticsearch-6.6.0.rpm
RUN cat elasticsearch-6.6.0.rpm--fim-policy.json
