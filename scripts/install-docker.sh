#!/usr/bin/env bash
set -e

echo "=== 🚀 Installing Docker Engine on Ubuntu ==="

# Ensure we’re running as root or via sudo
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run this script with sudo:"
  echo "   sudo $0"
  exit 1
fi

# 1. Remove old Docker versions
echo "=== 🧹 Removing old Docker versions (if any)..."
apt-get remove -y docker docker-engine docker.io containerd runc || true

# 2. Update packages and install prerequisites
echo "=== ⚙️ Installing dependencies..."
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release

# 3. Add Docker’s official GPG key
echo "=== 🔑 Adding Docker’s official GPG key..."
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 4. Set up the stable repository
echo "=== 📦 Adding Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. Install Docker Engine, CLI, containerd, and Compose plugin
echo "=== 🐳 Installing Docker Engine and Compose..."
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 6. Enable and start Docker
echo "=== 🔧 Enabling and starting Docker..."
systemctl enable docker
systemctl start docker

# 7. Add current user to the docker group (non-root access)
if id -nG "$SUDO_USER" | grep -qw "docker"; then
  echo "=== 👤 User '$SUDO_USER' is already in the docker group."
else
  echo "=== 👤 Adding user '$SUDO_USER' to the docker group..."
  usermod -aG docker "$SUDO_USER"
  echo "⚠️  Please log out and back in (or run 'newgrp docker') to apply group changes."
fi

# 8. Verify installation
echo "=== ✅ Verifying Docker installation..."
docker run --rm hello-world

echo "=== 🎉 Docker installation complete! ==="
echo "Run 'docker ps' to verify that Docker is working."
