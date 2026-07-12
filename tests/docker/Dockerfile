# Testing-only Mail-in-a-Box image. NOT FOR PRODUCTION.
# Runs systemd as PID 1 so the setup scripts' service/systemctl calls work
# unmodified. Provisioning (setup/start.sh) runs on first boot, not at build
# time, because systemd is not PID 1 during `docker build`.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    container=docker \
    MIAB_TEST_MODE=1 \
    PRIMARY_HOSTNAME=box.test.lan

# systemd + the tools setup and the lab defaults need. Two packages exist on a
# real Ubuntu Server but not in the stripped ubuntu:22.04 image, and setup/start.sh
# assumes both are already present before it installs anything:
#   - locales: provides locale-gen, which start.sh calls for its UTF-8 setup.
#   - python3: start.sh runs setup/migrate.py (shebang /usr/bin/python3) at
#     first-boot BEFORE setup/system.sh installs the Python stack; and our
#     NONINTERACTIVE=1 test mode skips the questions.sh block that would otherwise
#     apt-install it. Pre-installing matches a real server, not a workaround.
# locale-gen en_US.UTF-8 up front silences a benign setlocale warning and mirrors
# a normal Ubuntu install where that locale is already generated.
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus git curl ca-certificates sudo iproute2 locales python3 \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Container hygiene for systemd-as-PID-1: drop units that don't apply in a
# container so boot is clean and fast.
RUN systemctl mask \
        dev-hugepages.mount sys-fs-fuse-connections.mount \
        systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
        systemd-modules-load.service getty.target console-getty.service \
        systemd-firstboot.service

# The MiaB source. Canonical location is /root/mailinabox.
COPY . /root/mailinabox
WORKDIR /root/mailinabox

# First-boot provisioning oneshot (from Task 3).
COPY tests/docker/miab-provision.service /etc/systemd/system/miab-provision.service
COPY tests/docker/miab-provision.sh /usr/local/bin/miab-provision.sh
RUN chmod +x /usr/local/bin/miab-provision.sh \
    && systemctl enable miab-provision.service

STOPSIGNAL SIGRTMIN+3
EXPOSE 25 465 587 993 995 4190 80 443
CMD ["/lib/systemd/systemd"]
