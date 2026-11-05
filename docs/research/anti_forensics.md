# Anti-Forensic Detection Engine Specification

## Detected Anti-Forensic Behavior Categories

1. **Log Deletion (`log_deletion`):**
   - Command Patterns: `rm -rf /var/log/*`, `truncate -s 0 /var/log/syslog`, `> /var/log/audit/audit.log`
   - Target Artifacts: `/var/log/syslog`, `/var/log/audit/audit.log`, `/var/log/auth.log`
   - TCS Penalty: $-20\%$

2. **History Clearing (`history_clearing`):**
   - Command Patterns: `history -c`, `rm ~/.bash_history`, `unset HISTFILE`, `HISTFILE=/dev/null`
   - Target Artifacts: `~/.bash_history`, `~/.zsh_history`, memory buffer
   - TCS Penalty: $-10\%$

3. **Audit Shutdown (`audit_shutdown`):**
   - Command Patterns: `systemctl stop auditd`, `auditctl -e 0`, `killall auditd`, `service auditd stop`
   - Target Artifacts: `auditd` daemon, `kauditd` kernel buffer, audit rules
   - TCS Penalty: $-25\%$

4. **Secure Deletion (`secure_deletion`):**
   - Command Patterns: `shred -u file`, `srm file`, `dd if=/dev/zero of=file`
   - Target Artifacts: Payload binary, sector storage
   - TCS Penalty: $-15\%$

5. **Timestamp Manipulation (`timestamp_manipulation`):**
   - Command Patterns: `touch -t 202001010000 file`, `touch -r reference_file target`
   - Target Artifacts: Inode `mtime`/`atime` stat attributes
   - TCS Penalty: $-10\%$

6. **Time Changes (`time_change`):**
   - Command Patterns: `date --set="..."`, `timedatectl set-time "..."`
   - Target Artifacts: System wall clock, NTP synchronization state
   - TCS Penalty: $-15\%$
