FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y git
RUN wget -q -O- https://s3.amazonaws.com/download.fpcomplete.com/ubuntu/fpco.key | sudo apt-key add -
RUN echo 'deb http://download.fpcomplete.com/ubuntu/trusty stable main'|sudo tee /etc/apt/sources.list.d/fpco.list
RUN apt-get update && apt-get install stack -y
RUN apt-get install -y libpq-dev
RUN git clone https://github.com/begriffs/postgrest.git postgrest
RUN cd postgrest && stack build --install-ghc
RUN cd postgrest && stack install --allow-different-user --local-bin-path /usr/local/bin

ENTRYPOINT ["/run.sh"]
