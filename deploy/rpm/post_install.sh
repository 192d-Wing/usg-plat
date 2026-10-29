# NIST 800-53: AC-6, CM-6 - create the service account and give the config
# its baseline ownership: readable by platd, writable only by root.
# AU-9 - create /var/log/plat (plat:plat-log 2750) before the first start.
systemd-sysusers /usr/lib/sysusers.d/plat.conf
chown root:plat /etc/plat /etc/plat/platd.toml
chmod 0750 /etc/plat
chmod 0640 /etc/plat/platd.toml
systemd-tmpfiles --create /usr/lib/tmpfiles.d/plat.conf
systemctl daemon-reload >/dev/null 2>&1 || :
