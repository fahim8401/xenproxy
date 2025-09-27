#!/bin/sh
# Install services based on environment variables

if [ "$ENABLE_SSH" = "true" ]; then
  apk add --no-cache openssh
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
  echo "ListenAddress $CONTAINER_IP" >> /etc/ssh/sshd_config
  adduser -D -s /bin/sh $USERNAME
  mkdir -p /home/$USERNAME/.ssh
  echo "$SSH_KEY" > /home/$USERNAME/.ssh/authorized_keys
  chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
fi

if [ "$ENABLE_SOCKS5" = "true" ]; then
  apk add --no-cache dante-server
  # TODO: Configure Dante with username/password
fi

if [ "$ENABLE_HTTP" = "true" ]; then
  apk add --no-cache tinyproxy
  # TODO: Configure TinyProxy with basic auth
fi

# Start enabled services
rc-service sshd start 2>/dev/null || true
rc-service danted start 2>/dev/null || true
rc-service tinyproxy start 2>/dev/null || true
