#!/bin/sh

export G_MESSAGES_DEBUG=all

XDG_CONFIG_DIRS=/container/etc /usr/libexec/cockpit-ws --for-tls-proxy -p 9090 &

/container/cockpit-cloud-connector \
    --key /container/secrets/server.key \
    --cert /container/secrets/server.crt \
    --peer-cert /container/secrets/client.crt \
    server -p 8080 /tmp/socket
