FROM registry.fedoraproject.org/fedora:latest as builder
RUN dnf install --setopt=install_weak_deps=False -y glib2-devel make gcc
COPY src /tmp/src
RUN make -C /tmp/src

FROM registry.fedoraproject.org/fedora:latest
RUN dnf install --setopt=install_weak_deps=False -y socat cockpit-ws
RUN dnf install --setopt=install_weak_deps=False -y strace
ADD . /container
COPY --from=builder /tmp/src/cockpit-cloud-connector /container
EXPOSE 8080
EXPOSE 9090
CMD ["/container/run.sh"]
