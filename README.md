# LXC Multi-Protocol IP Gateway Admin Panel

A production-ready Python Flask application for managing a secure, multi-protocol IP gateway using LXC containers. All monitoring, management, and configuration are accessible through a custom admin panel.

---

## Features

- **LXC Container Orchestration:** One unprivileged container per IP, with resource limits and protocol selection (SSH, SOCKS5, HTTP, WireGuard).
- **Admin Panel:** Custom UI (Flask + Jinja2, no external CSS frameworks), real-time stats, dark/light mode, bulk actions, logs.
- **Security:** Argon2 password hashing, CSRF protection, rate limiting, input validation, HTTPS-only in production.
- **Monitoring:** Built-in host and container resource monitoring, abuse detection, auto-recovery, audit logs.
- **System Management:** Linux bridge, NAT, auto IP assignment, PostgreSQL backend.

---

## Project Structure

```
app.py
models.py
auth.py
lxc_manager.py
system_manager.py
monitor.py
requirements.txt
README.md
lxc-templates/
    alpine-config
    setup-services.sh
static/
    css/admin.css
    js/admin.js
    js/charts.js
templates/
    base.html
    login.html
    dashboard.html
    containers.html
    container_detail.html
    users.html
    system_settings.html
    logs.html
```

---

## Deployment

### Prerequisites

- Ubuntu 22.04 LTS
- LXC 5.0+ (`apt install lxc lxc-templates bridge-utils`)
- PostgreSQL 14+ (`apt install postgresql postgresql-client`)
- Python 3.10+ (`apt install python3-pip`)
- iptables, iproute2

### Installation

1. Clone the repo and install Python dependencies:
    ```
    pip install -r requirements.txt
    ```
2. Configure PostgreSQL and set `DATABASE_URL` in your environment:
    ```
    export DATABASE_URL=postgresql://postgres:postgres@localhost/ipgw
    ```
3. Run the app:
    ```
    python app.py
    ```
4. Access the admin panel at [http://localhost:3030](http://localhost:3030)

### Production

- Use Gunicorn and Nginx as a reverse proxy (HTTPS required).
- Set `SESSION_COOKIE_SECURE=True` and a strong `SECRET_KEY`.
- Run as a non-root user with sudo access to LXC and networking commands.

---

## Security

- Admin login with Argon2 hashed passwords
- CSRF protection on all forms
- Rate limiting: 5 failed logins/minute, 100 requests/minute per IP
- All API endpoints require admin authentication
- Input validation for usernames, IPs, SSH keys
- Unprivileged LXC containers with resource limits

---

## Monitoring & Abuse Prevention

- Real-time host and container stats (CPU, memory, disk, bandwidth)
- Health checks for all protocols (SSH, SOCKS5, HTTP, WireGuard)
- Abuse detection: high bandwidth, port scanning, excessive connections
- Auto-disable containers on abuse, admin alerts

---

## Backup & Restore

- Database backup script included
- Container configuration backup
- Restore procedure documented

---

## License

MIT License

---

## Credits

- Alpine Linux, LXC, Flask, Argon2, Chart.js
