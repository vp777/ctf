if [[ -z "$1" ]]; then
    echo "I need the hostname/IP through which the container is reachable"
    echo "Run again with: ./docker_run.sh X.X.X.X"
    exit
fi

docker run --rm -e "EXTERNAL_IP=$1" -p 5000:5000 -p 9999:9999 -d hellxss

