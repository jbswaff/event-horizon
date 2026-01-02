# event-horizon
Event Horizon is a minimal “single button” web page to temporarily disable Pi-hole v6 blocking across one or more Pi-hole instances using the Pi-hole v6 API.

## Important
- **Pi-hole v6 only**. Not compatible with v5.
- **No TLS and no login** by design. You must restrict access (VLAN/firewall).

## Install (one-shot)
curl -fsSL https://raw.githubusercontent.com/jbswaff/event-horizon/main/install.sh | sudo bash
