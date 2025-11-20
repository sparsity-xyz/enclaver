#!/bin/bash
set -euo pipefail

echo "Starting EC2 user data script for Nitro Enclave testing..."

# Detect package manager (AL2 uses yum, AL2023 uses dnf)
if command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
else
    echo "Error: No supported package manager found"
    exit 1
fi

# 1. Install Docker
echo "Installing Docker..."
if [ "$PKG_MGR" = "yum" ]; then
    yum install -y docker
else
    dnf install -y docker
fi

# Start Docker early so it's available for later steps
systemctl start docker
systemctl enable docker

# 2. Install Nitro Enclave packages
echo "Installing Nitro Enclave tools..."
if [ "$PKG_MGR" = "yum" ]; then
    amazon-linux-extras install -y aws-nitro-enclaves-cli
    yum install -y aws-nitro-enclaves-cli-devel
else
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
fi

# 3. Add ec2-user to required groups
echo "Adding ec2-user to docker and ne groups..."
usermod -aG docker ec2-user
usermod -aG ne ec2-user

# 4. Configure allocator.yaml and hugepages
echo "Configuring allocator.yaml and hugepages..."

# Get total CPU cores and RAM
TOTAL_CPUS=$(nproc)
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')

# Reserve 2 CPU and 2048MB for system
ENCLAVE_CPUS=$((TOTAL_CPUS - 2))
ENCLAVE_RAM_MB=$((TOTAL_RAM_MB - 2048))

# Create allocator.yaml
mkdir -p /etc/nitro_enclaves
cat > /etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: ${ENCLAVE_RAM_MB}
cpu_count: ${ENCLAVE_CPUS}
EOF

# Configure hugepages
echo "vm.nr_hugepages=$((ENCLAVE_RAM_MB / 2))" >> /etc/sysctl.conf
sysctl -p

# Enable and start nitro-enclaves-allocator service
systemctl enable nitro-enclaves-allocator.service
systemctl start nitro-enclaves-allocator.service

# 5. Install enclaver from latest release
echo "Installing enclaver..."
ENCLAVER_LATEST=$(curl -s https://api.github.com/repos/sparsity-xyz/enclaver/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
curl -L -o /tmp/enclaver.tar.gz "https://github.com/sparsity-xyz/enclaver/releases/download/${ENCLAVER_LATEST}/enclaver-linux-x86_64-${ENCLAVER_LATEST}.tar.gz"
tar -xzf /tmp/enclaver.tar.gz -C /tmp
mv /tmp/enclaver-linux-x86_64-${ENCLAVER_LATEST}/enclaver /usr/local/bin/enclaver
chmod +x /usr/local/bin/enclaver
rm -rf /tmp/enclaver.tar.gz /tmp/enclaver-linux-x86_64-${ENCLAVER_LATEST}

# 6. Install git (useful for cloning test repos)
echo "Installing git..."
$PKG_MGR install -y git

# 7. Create a working directory for testing
mkdir -p /opt/enclave-test
chown ec2-user:ec2-user /opt/enclave-test

# 8. Setup auto-shutdown if enabled
if [ "${AUTO_SHUTDOWN:-true}" = "true" ]; then
    echo "Setting up auto-shutdown in 24 hours..."

    # Get instance details
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

    # Create shutdown script
    cat > /usr/local/bin/auto-shutdown.sh <<'SHUTDOWN_SCRIPT'
#!/bin/bash
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
echo "Auto-shutdown triggered for instance $INSTANCE_ID in region $REGION"
aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region $REGION
SHUTDOWN_SCRIPT

    chmod +x /usr/local/bin/auto-shutdown.sh

    # Schedule shutdown in 24 hours using at command
    $PKG_MGR install -y at
    systemctl enable atd
    systemctl start atd
    echo "/usr/local/bin/auto-shutdown.sh" | at now + 24 hours

    echo "Auto-shutdown scheduled for $(date -d '+24 hours')"
fi

echo "EC2 user data script completed successfully!"
echo ""
echo "Instance is ready for Nitro Enclave testing with enclaver."
echo "Working directory: /opt/enclave-test"
echo ""
echo "Quick test commands:"
echo "  sudo nitro-cli describe-enclaves"
echo "  enclaver --version"
echo "  docker --version"
