#!/bin/sh
# Install services based on environment variables

if [ "$ENABLE_SSH" = "true" ]; then
  apk add --no-cache openssh
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  echo "ListenAddress $CONTAINER_IP" >> /etc/ssh/sshd_config
  
  if [ "$AUTH_METHOD" = "ssh" ]; then
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
    adduser -D -s /bin/sh $USERNAME
    mkdir -p /home/$USERNAME/.ssh
    echo "$SSH_KEY" > /home/$USERNAME/.ssh/authorized_keys
    chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
  elif [ "$AUTH_METHOD" = "password" ]; then
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    adduser -D -s /bin/sh $USERNAME
    echo "$USERNAME:$PASSWORD" | chpasswd
  fi
fi

if [ "$ENABLE_SOCKS5" = "true" ]; then
  apk add --no-cache dante-server
  cat > /etc/dante.conf <<EOF
logoutput: syslog
internal: 0.0.0.0 port = 1080
external: $CONTAINER_IP
method: username none
user.notprivileged: nobody
client pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  log: connect disconnect error
}
socks pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  command: bind connect udpassociate
  log: connect disconnect error
}
EOF
  adduser -D -s /bin/sh socksuser
  echo "socksuser:$(openssl rand -base64 12)" | chpasswd
fi

if [ "$ENABLE_HTTP" = "true" ]; then
  apk add --no-cache tinyproxy
  sed -i 's/^Allow /#Allow /' /etc/tinyproxy/tinyproxy.conf
  sed -i 's/^#BasicAuth user password/BasicAuth httpuser $(openssl rand -base64 12)/' /etc/tinyproxy/tinyproxy.conf
  sed -i 's/^Port .*/Port 8080/' /etc/tinyproxy/tinyproxy.conf
  adduser -D -s /bin/sh httpuser
  echo "httpuser:$(openssl rand -base64 12)" | chpasswd
fi

# Start enabled services
rc-service sshd start 2>/dev/null || true
rc-service danted start 2>/dev/null || true
rc-service tinyproxy start 2>/dev/null || true
