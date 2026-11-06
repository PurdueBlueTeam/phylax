#!/bin/sh
# c2-facts.sh -- C2 Linux host facts collector (read-only).
#
# Answers the environment questions E1-E5, E7-E11, E14, E17, E19, E20, O5 from
# docs/impl/invitational-data.md: one timestamped directory of plain text plus
# one archive. Observe only: it reads what is there (getent, ss, list/show
# queries, config dumps) and never changes it. Password hashes are never read;
# accounts come from NSS only.
#
# Usage: sh c2-facts.sh

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "$HERE/lib.sh"

inv_init c2 || exit 1

# E1: kernel version, architecture, BTF and the config options the design
# decisions (eBPF, fanotify, inet_diag, nf_tables, audit) hinge on.
inv_run kernel uname -a
inv_run procversion cat /proc/version
inv_run btf ls -l /sys/kernel/btf/vmlinux
inv_run kconfig sh -c '
    pat="FANOTIFY|NETLINK_DIAG|INET_DIAG|AUDIT|BPF|NF_TABLES"
    f=/boot/config-$(uname -r)
    if [ -f "$f" ]; then
        grep -E "$pat" "$f"
    elif [ -f /proc/config.gz ]; then
        zcat /proc/config.gz | grep -E "$pat"
    else
        echo "no kernel config: neither $f nor /proc/config.gz"
        exit 1
    fi'

# E2: OS release and the package set (which product versions are installed).
inv_run osrelease cat /etc/os-release
inv_run packages sh -c 'dpkg -l 2>&1 || rpm -qa 2>&1'

# E3: versions of the scored products, each tried even when absent; the exit
# code follows every line so a missing tool is obvious.
inv_run versions sh -c '
    for c in "sshd -V" "apachectl -v" "nginx -v" "php -v" "postconf mail_version" \
        "dovecot --version" "mysql --version" "named -v"; do
        printf "=== %s\n" "$c"
        sh -c "$c 2>&1"
        printf "exit: %s\n" "$?"
    done'

# E4: does any scored product run in a container?
inv_run containers sh -c '
    docker ps -a 2>&1; printf "docker exit: %s\n" "$?"
    podman ps -a 2>&1; printf "podman exit: %s\n" "$?"'

# E5: listeners and everything that starts at boot.
inv_run listeners ss -tulnpe
inv_run unixsockets ss -xlp
inv_run passwd getent passwd # inv:ro: NSS accounts only, never the hash file
inv_run group getent group
inv_run sudoers sh -c 'cat /etc/sudoers /etc/sudoers.d/* 2>&1'
inv_run lastlog sh -c 'last -n 50 2>&1'
inv_run authkeys sh -c 'find / -xdev -name authorized_keys -exec ls -l {} + 2>/dev/null'
inv_run cron sh -c 'ls -l /etc/cron* 2>&1; crontab -l -u root 2>&1' # inv:ro: lists only
inv_run timers systemctl list-timers --all # inv:ro: list only
inv_run units systemctl list-units --all --type=service # inv:ro: list only

# E9: logging state: audit status and loaded rules, read only.
inv_run auditstate sh -c '
    auditctl -s 2>&1; printf "auditctl -s exit: %s\n" "$?" # inv:ro: status only
    auditctl -l 2>&1; printf "auditctl -l exit: %s\n" "$?" # inv:ro: list only'
inv_run auditd systemctl show auditd -p ActiveState -p MainPID # inv:ro: show only
inv_run logconf sh -c 'cat /etc/rsyslog.conf /etc/systemd/journald.conf 2>&1'
inv_run journal journalctl --disk-usage

# E10: firewall ruleset, read only.
inv_run firewall sh -c '
    nft list ruleset 2>&1; printf "nft exit: %s\n" "$?" # inv:ro: lists the ruleset only
    iptables -S 2>&1; printf "iptables exit: %s\n" "$?" # inv:ro: lists the ruleset only'

# E11: topology as the host sees it.
inv_run network sh -c 'ip -br a 2>&1; ip r 2>&1; cat /etc/resolv.conf 2>&1'

# E14: resource headroom. E20: boot profile. O5: clock offset.
inv_run disk sh -c 'df -hT 2>&1; df -i 2>&1; lsblk 2>&1'
inv_run memory free -m
inv_run cpu sh -c 'nproc; cat /proc/loadavg'
inv_run boot sh -c 'uptime -s; systemd-analyze 2>&1'
inv_run ntp sh -c 'chronyc tracking 2>&1; timedatectl 2>&1'

# E10: effective configuration of the scored services (read-only dumps).
inv_run sshd sshd -T
inv_run mail sh -c 'postconf -n 2>&1; doveconf -n 2>&1'
inv_run web sh -c 'apachectl -S 2>&1; apachectl -M 2>&1; nginx -T 2>&1'

# E19: Splunk apps and version.
inv_run splunk sh -c '
    ls /opt/splunk/etc/apps 2>&1
    if [ -x /opt/splunk/bin/splunk ]; then
        /opt/splunk/bin/splunk version 2>&1
    fi'

# E17: sizes of the data the golden backup has to carry.
inv_run datasizes sh -c '
    du -sx /var/www /var/lib/mysql /var/lib/pgsql /var/lib/splunk \
        /opt/splunk/var /var/spool/mail /var/mail /home 2>&1'

inv_pack
