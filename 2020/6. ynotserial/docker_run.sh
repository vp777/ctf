PORT=${1:-9999}
docker run --rm -e "PORT=${PORT}" -p $PORT:$PORT -d ynotserial

