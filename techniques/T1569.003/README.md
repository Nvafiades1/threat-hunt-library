# Systemctl

**Technique ID:** T1569.003

**Description:**
Adversaries may abuse systemctl to execute commands or programs. Systemctl is the primary interface for systemd, the Linux init system and service manager. Typically invoked from a shell, Systemctl can also be integrated into scripts or applications.   

Adversaries may use systemctl to execute commands or programs as [Systemd Service](https://attack.mitre.org/techniques/T1543/002)s. Common subcommands include: `systemctl start`, `systemctl stop`, `systemctl enable`, `systemctl disable`, and `systemctl status`.(Citation: Red Hat Systemctl 2022)
