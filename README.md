# LXC Multi-Protocol IP Gateway Admin Panel

A production-ready Python Flask application for managing a secure, multi-protocol IP gateway using LXC containers. All monitoring, management, and configuration are accessible through a custom admin panel.

---

## Features

- **LXC Container Orchestration:** One unprivileged container per IP, with resource limits and protocol selection (SSH, SOCKS5, HTTP, WireGuard).
- **Admin Panel:** Custom UI (Flask + Jinja2, no external CSS frameworks), real-time stats, dark/light mode, bulk actions, logs.
- **Security:** Argon2 password hashing, CSRF protection, rate limiting, input validation, HTTPS-only in production.
- **Monitoring:** Built-in host and container resource monitoring, abuse detection, auto-recovery, audit logs.
- **System Management:** Linux bridge, NAT, auto IP assignment, PostgreSQL backend.
- **Fully Automated Install:** Use `install.sh` for A-Z setup (system deps, DB, LXC, templates, static, DB init).
- **Root-Compatible:** Works on both Ubuntu and AlmaLinux as root (or with sudo).

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
install.sh
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

## Quick Start (A-Z Automated, Ubuntu/AlmaLinux, root or sudo)

1. **Clone the repo and run the installer as root:**
    ```bash
    git clone https://github.com/fahim8401/xenproxy.git
    cd xenproxy
    chmod +x install.sh
    sudo ./install.sh
    # or: su - && ./install.sh
    ```

2. **Run the app:**
    ```bash
    source venv/bin/activate
    export DATABASE_URL=postgresql://postgres:postgres@localhost/ipgw
    python app.py
    ```

3. **Access the admin panel:**  
   [http://localhost:3030](http://localhost:3030)

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

## OS Compatibility

- **Ubuntu 22.04+** (Debian-based)
- **AlmaLinux 8+/CentOS/RHEL** (RedHat-based)
- Must be run as root or with sudo for full automation

---

## License

MIT License

---

## Credits

- Alpine Linux, LXC, Flask, Argon2, Chart.js
