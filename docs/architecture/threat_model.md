# CHRONOS-FL Threat Model

## Assumptions & Threat Environment
1. **Adversary Privilege:** The adversary has gained root / sudo access on the victim host.
2. **Intent:** The adversary intends to wipe logs, clear history, and obfuscate timeline evidence to prevent incident attribution.
3. **Targeted Log Vectors:** `/var/log/*`, `/var/log/audit/`, `~/.bash_history`, system wall clock (`date --set`), inode timestamps (`touch -t`).

## Defense & Security Guarantees
1. **Kernel-Level Sensor Isolation:** System call events are intercepted at kernel tracepoints (`sys_enter_execve`, `sys_enter_connect`) via eBPF before userspace log deletion takes effect.
2. **Instant Volatile Snapshots:** Detection of anti-forensic commands immediately captures running processes, active sockets, open file descriptors, and loaded kernel modules.
3. **Cryptographic Tamper-Evident Ledger:** Evidence events are committed into SHA-256 hash chains. Post-hoc modification of sealed events breaks the hash sequence and immediately triggers `TAMPERING_DETECTED`.
