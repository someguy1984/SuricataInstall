# Mock droplets for server_edr_solution: two Ubuntu 26.04 machines with systemd as PID 1,
# so they behave like DigitalOcean droplets (units, journald, timers) and the planned
# installers can be run inside them later.
#
#   docker compose build          (from server_edr_solution/mock, or use ./mock.sh up)
#
# Targets:  base -> hub   (the hub box; a TLS placeholder on :8443 until `mock.sh install-hub` replaces it)
#           base -> web   (nginx + PHP 8.5 serving web.dev.local on :80 and :443, and sshd on :22)

ARG UBUNTU_TAG=26.04

FROM ubuntu:${UBUNTU_TAG} AS base
ENV DEBIAN_FRONTEND=noninteractive \
    container=docker \
    LANG=C.UTF-8
# systemd as init, plus what a droplet has and what the planned kits need
# (python3 + openssl for the agent/hub, nftables/iptables for bans and the DNS lockdown,
#  iproute2 for ss, kmod for the modprobe checks).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus ca-certificates curl openssl python3 \
      nftables iptables iproute2 iputils-ping procps kmod less nano \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 # units that make no sense in a container or that slow down boot
 && systemctl mask \
      getty.target console-getty.service systemd-logind.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-udevd-control.socket \
      systemd-udevd-kernel.socket systemd-firstboot.service systemd-remount-fs.service \
      sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount \
      systemd-modules-load.service systemd-sysctl.service \
      proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount \
 # a droplet-sized journal
 && mkdir -p /etc/systemd/journald.conf.d \
 && printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/mock.conf
COPY common/mock-tls.sh /usr/local/sbin/mock-tls
RUN chmod 0755 /usr/local/sbin/mock-tls
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

# --------------------------------------------------------------------------- hub
FROM base AS hub
COPY hub/mock-tls.service hub/mock-hub-placeholder.service /etc/systemd/system/
RUN systemctl enable mock-tls.service mock-hub-placeholder.service

# --------------------------------------------------------------------------- web
FROM base AS web
# openssh-server: the client installer's `--yes` confirms itself only when sshd listens on port 22 (client install.sh,
# wait_confirm). Nothing connects to it; it only has to be there, as on a droplet.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx php8.5-fpm php8.5-cli openssh-server \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default
COPY web/web.dev.local.conf /etc/nginx/sites-available/web.dev.local
COPY web/web.dev.local.common /etc/nginx/sites-available/web.dev.local.common
COPY web/public/ /var/www/web.dev.local/public/
COPY web/mock-tls.service /etc/systemd/system/
RUN ln -s /etc/nginx/sites-available/web.dev.local /etc/nginx/sites-enabled/web.dev.local \
 && chown -R root:root /var/www/web.dev.local && chmod -R a+rX /var/www/web.dev.local \
 && systemctl enable mock-tls.service nginx.service php8.5-fpm.service \
 && { systemctl enable ssh.socket 2>/dev/null || systemctl enable ssh.service; }
