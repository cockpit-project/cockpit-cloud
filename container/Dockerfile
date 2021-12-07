FROM registry.fedoraproject.org/fedora:35
RUN dnf install --setopt=install_weak_deps=False -y socat cockpit-ws
RUN dnf install --setopt=install_weak_deps=False -y strace
ADD . /container
EXPOSE 8080
EXPOSE 9090
CMD ["/container/run.sh"]
