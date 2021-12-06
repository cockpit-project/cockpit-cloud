#!/bin/sh

/container/session-server \
    --key /container/server.key \
    --cert /container/server.crt \
    --peer-cert /container/client.crt \
    8080
