# EC2 Provision Tool for Enclaver Testing

Standalone EC2 provisioning tool for launching Nitro Enclave-enabled instances for testing enclaver. This tool creates fully configured instances with all necessary Nitro Enclave tools and enclaver installed.

## Features

- Launch EC2 instances with Nitro Enclaves enabled
- Automatic installation of AWS Nitro Enclave CLI tools
- Automatic installation of latest enclaver from releases
- Pre-configured enclave resource allocation (CPU/RAM)
- Docker installed and configured
- Ready-to-use testing environment at `/opt/enclave-test`
- Configure via YAML file (ec2.yaml)

## Installation

```bash
cd ec2-provision
pip install -r requirements.txt
```

## Configuration

### 1. AWS Credentials

The tool supports multiple ways to provide AWS credentials:

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-west-1
```

**Option B: .env File**
Create a `.env` file in the project root or specify it with `--env`:
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-west-1
```

**Option C: AWS Credentials File**
Use the standard AWS credentials file at `~/.aws/credentials`

### 2. EC2 Configuration (ec2.yaml)

Edit `ec2.yaml` to configure your EC2 instances:

```yaml
# Per-region AMI mapping (use AMIs with Nitro Enclave support)
ami_by_region:
  us-west-1: "ami-0be87055cd1c16e86"
  us-east-1: "ami-0be87055cd1c16e86"

# Fallback AMI for all regions
ami_id: "ami-0be87055cd1c16e86"

# Instance type (must support Nitro Enclaves - c6i, c6a, m5, etc.)
instance_type: "c6i.2xlarge"

# SSH key pair
key_name: "app-node-key"

# EBS configuration
ebs:
  device_name: "/dev/xvda"
  encrypted: false
  delete_on_termination: true
  snapshot_id: "snap-016e261f1627f4b18"
  volume_size: 50
  volume_type: "gp3"
  iops: 3000
  throughput: 125

# Network configuration
network:
  security_group_ids:
    - "sg-026d4c8f6275bc43e"
  subnet_id: "subnet-0b43f3a7bdc5166b7"
  associate_public_ip: true

# Nitro Enclave options (must be enabled)
enclave:
  enabled: true

# Metadata service options
metadata:
  http_endpoint: "enabled"
  http_put_response_hop_limit: 2
  http_tokens: "optional"

# Private DNS options
private_dns:
  hostname_type: "ip-name"
  enable_dns_a: true
  enable_dns_aaaa: false

# IAM instance profile (needs permissions for Secrets Manager if using in user_data)
iam_instance_profile_arn: "arn:aws:iam::004118891089:instance-profile/Nova-App-Node-Role"

# Instance tags
tags:
  Name: "enclaver-test-node"
  Service: "enclaver-testing"
```

## Usage

### Basic Usage

Provision an instance in a specific region:

```bash
python ec2_provision.py --region us-west-1
```

**Auto-Shutdown Feature:**
By default, instances are configured to automatically terminate after 24 hours. To disable this:

```bash
AUTO_SHUTDOWN=false python ec2_provision.py --region us-west-1
```

### Advanced Usage

**Use a custom config file:**
```bash
python ec2_provision.py --region us-west-1 --config my-ec2.yaml
```

**Specify a .env file:**
```bash
python ec2_provision.py --region us-east-1 --env /path/to/.env
```

**Enable verbose logging:**
```bash
python ec2_provision.py --region us-west-1 --verbose
```

### Example Output

```
============================================================
EC2 Instance Provisioned Successfully!
============================================================
Instance ID:   i-0abc123def456789
Region:        us-west-1
Private IP:    10.0.1.123
CPU Total:     8 vCPUs
RAM Total:     16384 MiB
CPU Free:      6 vCPUs
RAM Free:      14336 MiB
Created At:    2025-11-19T10:30:45.123456
============================================================
```

## What Gets Installed

The user data script automatically sets up the instance with:

1. **AWS Nitro Enclave CLI tools** - For managing enclaves
2. **Nitro Enclave allocator** - Configured to reserve 2 CPUs and 2GB RAM for the host system
3. **Hugepages** - Configured for enclave memory allocation
4. **Docker** - Latest version, enabled and started
5. **Enclaver** - Latest release from sparsity-xyz/enclaver
6. **Git** - For cloning test repositories
7. **Working directory** - `/opt/enclave-test` for your testing
8. **Auto-shutdown timer** - (if AUTO_SHUTDOWN=true) Automatically terminates the instance after 24 hours to prevent unnecessary costs

## Testing Enclaver

Once the instance is provisioned, SSH into it and start testing:

```bash
# SSH into the instance
ssh -i your-key.pem ec2-user@<instance-ip>

# Verify Nitro Enclave setup
sudo nitro-cli describe-enclaves

# Check enclaver version
enclaver --version

# Check Docker
docker --version

# Go to testing directory
cd /opt/enclave-test

# Clone your test repo or create test files
git clone <your-repo>

# Run enclaver commands
enclaver build
enclaver run
```

## Enclave Resource Allocation

The instance automatically reserves:
- **Host System**: 2 vCPUs + 2048 MiB RAM
- **Enclave Available**: Remaining CPUs and RAM

For example, on a `c6i.2xlarge` (8 vCPU, 16GB RAM):
- Host gets: 2 vCPUs, 2 GB RAM
- Enclave can use: 6 vCPUs, 14 GB RAM

## Troubleshooting

### No AWS Credentials Error
```
RuntimeError: No AWS credentials configured
```
**Solution**: Ensure AWS credentials are provided via environment variables, .env file, or AWS credentials file.

### AMI Not Configured Error
```
RuntimeError: AMI ID not configured for region us-west-1
```
**Solution**: Add the AMI ID for your region in `ec2.yaml` under `ami_by_region` or set a fallback `ami_id`.

### Invalid AMI ID Error
```
RuntimeError: Invalid AMI ID configured in ec2.yaml
```
**Solution**: Ensure the AMI ID starts with "ami-" and is valid for your region.

### Instance Type Doesn't Support Enclaves
**Solution**: Use instance types that support Nitro Enclaves: c6i, c6a, c5, c5a, c5n, m5, m5a, m5n, r5, r5a, r5n, etc.

### AWS ClientError
```
AWS ClientError: InvalidAMIID.NotFound - The image id '[ami-xxx]' does not exist
```
**Solution**: Verify the AMI ID exists in the target region. AMIs are region-specific.

## Checking User Data Logs

To see if the user data script ran successfully:

```bash
# View cloud-init output log
sudo cat /var/log/cloud-init-output.log

# Check for errors
sudo grep -i error /var/log/cloud-init-output.log
```

## License

Part of the Sparsity Nova Platform.
