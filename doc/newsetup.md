# Pwnboard Setup
Written by Massimo Marino (max-49)

# Board Setup
The pwnboard requires a topology to run specifying what IP addresses are in the competition. Generate a topology.json file using `Topology-Generator/generator.py`. When finished, copy the topology.json file to the root directory. Topology-Generator comes from [here](https://github.com/RITRedteam/Topology-Generator)

To convert the topology to a board (so pwnboard can use it), use `gen_config.py`. Copy `scripts/gen_config.py` to the root directory (same directory as topology.json) and use the following command to convert it to a board

```bash
python3 gen_config.py topology.json board.json
```

board.json should be in the root directory as well.

## Deploying

Install the Docker engine using the instructions on the Docker website.

Docker makes deployment of the pwnboard very very simple. See [docker-compose.yml](../docker-compose.yml) for a well-commented example of a docker-compose file with basic configuration options.

You can deploy pwnboard with the following command:
```bash
docker compose up -d
```

## Troubleshooting

You might run into some issues while deploying the containers. Here are some issues that I ran into with solutions:

### Build hangs while installing packages on pwnboard container

> Check MTU of host using `ip link show \<networking interface\>` and note the number next to `mtu`. Then run the following command and note the MTU.

```bash
docker run --rm alpine sh -c "ip link show eth0"
```

> If this MTU is greater than the host MTU, lower the default docker networking MTU by running the following commands:

```bash
cat <<EOF > /etc/docker/daemon.json
{
  "mtu": 1400
}
EOF
systemctl restart docker
```

> Then you can rebuild the container

```bash
docker compose build --no-cache
docker compose up -d
```

2. Any error that says "disk quota exceeded"

> Try to increase the amount of space on whichever disk partition you are working on

## Notes about the pwnboard

Make sure that `SYSLOG_HOST` is receiving connections or PWNBOARD will lag
when trying to send SYSLOGS. If no syslog server is running, leave it blank.

Further configurations can be made to modify the behavior, the configurations can be set with[Environment Variables](./config.md). 

## SSL
In the future we would like to get this setup in docker
Generate Self-Signed SSL certificates
```
mkdir /etc/nginx/ssl
openssl req -x509 -nodes -new -batch -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt
```

> If you would like to use LetsEncrypt's Certbot, follow
[this guide](CERTBOT.md).
