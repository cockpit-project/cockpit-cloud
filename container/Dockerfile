FROM registry.fedoraproject.org/fedora:35
ADD . /container
RUN /container/install.sh
EXPOSE 8080
EXPOSE 9090
CMD ["/container/run.sh"]
