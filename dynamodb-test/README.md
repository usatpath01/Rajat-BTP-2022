## How to run the Docker services
- `docker compose up fluentd -d` to run fluentd for logging.
- `docker run \
    --name tracee --rm -it \
    --pid=host --cgroupns=host --privileged --log-driver=fluentd --log-opt tag="{{.Name}}" \
    -v /etc/os-release:/etc/os-release-host:ro \
    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
    aquasec/tracee:latest \
trace --trace container=new --trace event=open,openat,write` to run the tracee container for printing audit logs for every container (except fluentd).
- `docker compose up` to run the dynamodb and the aws-cli container.
