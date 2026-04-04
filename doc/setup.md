# PWNBoard Setup
Written by Massimo Marino (max-49)

## Deploying

Install the Docker engine using the instructions on the Docker website.

Docker makes deployment of the PWNBoard very very simple. See [docker-compose.yml](../docker-compose.yml) for a well-commented example of a docker-compose file with basic configuration options.

You can deploy PWNBoard with the following command:
```bash
docker compose up -d
```

## Troubleshooting

You might run into some issues while deploying the containers. Here are some issues that I ran into with solutions:

### Build hangs while installing packages on PWNBoard container

> Find networking interface using `ip a`. Check MTU of interface using `ip link show <interface>` and note the number next to `mtu`. Then run the following command and note the container MTU.

```bash
docker run --rm alpine sh -c "ip link show eth0"
```

> If this MTU is greater than the host MTU, lower the default Docker networking MTU by running the following commands:

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
