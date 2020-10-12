FROM buildkite/puppeteer:v1.15.0

WORKDIR /cxss

RUN apt-get update && npm i express cors

COPY docker_files/init.sh ./
COPY docker_files/admin.js ./
COPY docker_files/api-server.js ./
COPY docker_files/react-server.js ./
COPY docker_files/flag-server.js ./
ADD docker_files/build.tar.gz ./
RUN chmod +x ./init.sh

CMD ["./init.sh"]
