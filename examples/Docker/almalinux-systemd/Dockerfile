FROM almalinux:9
ENV container docker

WORKDIR /lib/systemd/system/sysinit.target.wants/
RUN for i in ; do [ "$i" == systemd-tmpfiles-setup.service ] || rm -f "$i"; done && \
    rm -rf /lib/systemd/system/multi-user.target.wants/ && \
    rm -rf /etc/systemd/system/.wants/ && \
    rm -rf /lib/systemd/system/local-fs.target.wants/ && \
    rm -f /lib/systemd/system/sockets.target.wants/udev && \
    rm -f /lib/systemd/system/sockets.target.wants/initctl && \
    rm -rf /lib/systemd/system/basic.target.wants/ && \
    rm -f /lib/systemd/system/anaconda.target.wants/*

# VOLUME [ “/sys/fs/cgroup” ]
CMD ["/usr/sbin/init"]
