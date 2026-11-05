# Evidence Survivability & Timeline Confidence Formulation

## 1. Evidence Survivability Score (ESS)
$$\text{ESS} = \left( \frac{\sum_{s \in \text{Surviving Sources}} w_s}{\sum_{s \in \text{All Expected Sources}} w_s} \right) \times 100\%$$

Default source weights ($w_s$):
- **eBPF Trace Sensor:** $3.0$
- **Network Packet / Flow Logs:** $3.0$
- **Audit Logs (`/var/log/audit`):** $2.5$
- **Systemd Journal / Syslog:** $1.5$
- **Shell Command History:** $1.0$

## 2. Timeline Confidence Score (TCS)
$$\text{TCS} = 100\% - P_{\text{missing}} - P_{\text{log\_deletion}} - P_{\text{history\_clearing}} - P_{\text{time\_manipulation}} - P_{\text{ledger\_tampering}}$$

Confidence Levels:
- **90.0% - 100.0%**: `HIGH` — Fully trustworthy timeline.
- **75.0% - 89.9%**: `MEDIUM` — Moderately trustworthy timeline.
- **50.0% - 74.9%**: `LOW` — Low timeline confidence.
- **< 50.0%**: `CRITICAL_TAMPERING` — Timeline integrity compromised.
