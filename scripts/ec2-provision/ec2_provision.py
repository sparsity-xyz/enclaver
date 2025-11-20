#!/usr/bin/env python3
"""
Standalone EC2 Provisioning Tool

This tool provisions EC2 instances with Nitro Enclaves based on configuration
from ec2.yaml. It's extracted from the registry-node workflow and can be used
independently.

Usage:
    python ec2_provision.py --region us-west-1
    python ec2_provision.py --region us-east-1 --config custom-ec2.yaml
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EC2ProvisionConfig:
    """Minimal configuration for EC2 provisioning."""

    def __init__(self, env_file: Optional[Path] = None):
        """Load configuration from environment file if provided."""
        self.aws_region = "us-west-1"
        self.aws_access_key_id = ""
        self.aws_secret_access_key = ""

        if env_file and env_file.exists():
            self._load_env_file(env_file)

    def _load_env_file(self, env_file: Path):
        """Load configuration from a .env file."""
        try:
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")

                        if key == "AWS_REGION":
                            self.aws_region = value
                        elif key == "AWS_ACCESS_KEY_ID":
                            self.aws_access_key_id = value
                        elif key == "AWS_SECRET_ACCESS_KEY":
                            self.aws_secret_access_key = value
        except Exception as e:
            logger.warning(f"Failed to load env file {env_file}: {e}")


def get_ec2_client(config: EC2ProvisionConfig, region: Optional[str] = None):
    """Return a boto3 EC2 client for the configured region.

    If AWS credentials are provided in config, use them. Otherwise rely
    on boto3's default credential chain (env vars, shared config, or instance
    profile).
    """
    use_region = region or config.aws_region
    creds = {}
    if config.aws_access_key_id and config.aws_secret_access_key:
        creds = {
            "aws_access_key_id": config.aws_access_key_id,
            "aws_secret_access_key": config.aws_secret_access_key,
        }

    return boto3.client("ec2", region_name=use_region, **creds)


def provision_ec2_instance(
    region: str,
    config: EC2ProvisionConfig,
    config_file: Path
) -> Dict[str, Any]:
    """Provision a new EC2 instance with Nitro Enclaves.

    Args:
        region: AWS region to provision in
        config: EC2ProvisionConfig with AWS credentials and settings
        config_file: Path to ec2.yaml configuration file

    Returns:
        Dictionary with instance details:
        {
            'instance_id': 'i-xxxxx',
            'region': 'us-west-1',
            'state': 'idle',
            'cpu_total': 8,
            'ram_mib_total': 16384,
            'cpu_free': 6,
            'ram_mib_free': 14336,
            'private_ip': '10.0.1.123',
            'created_at': '2025-11-19T...'
        }
    """
    logger.info(f"Starting EC2 provisioning in region={region}")

    # Load EC2 config from YAML file
    if not config_file.exists():
        logger.error("EC2 config file missing: %s", config_file)
        raise RuntimeError(
            f"EC2 config file not found at {config_file}. Create `ec2.yaml` with `ami_id` and `instance_type` keys."
        )

    try:
        cfg = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logger.error("Failed to parse EC2 config file %s: %s", config_file, e, exc_info=True)
        raise RuntimeError(f"Failed to parse EC2 config file {config_file}: {e}") from e

    # Allow per-region AMI mapping. If present, prefer that mapping.
    ami_by_region = cfg.get("ami_by_region") or {}
    ami_id = None
    if isinstance(ami_by_region, dict):
        ami_id = ami_by_region.get(region)

    # Fallback to a single `ami_id` key if no per-region mapping found
    if not ami_id:
        ami_id = cfg.get("ami_id")

    if not ami_id:
        logger.error("AMI ID not set for region %s in ec2.yaml (ami_by_region or ami_id)", region)
        raise RuntimeError(
            f"AMI ID not configured for region {region}: set `ami_by_region.{region}` or `ami_id` in ec2.yaml"
        )

    if not isinstance(ami_id, str) or not ami_id.startswith("ami-"):
        logger.error("Configured AMI ID appears invalid for region %s: %r", region, ami_id)
        raise RuntimeError(f"Invalid AMI ID configured in ec2.yaml for region {region}: {ami_id!r}")

    instance_type = cfg.get("instance_type", "c6i.2xlarge")
    logger.info(f"Using AMI: {ami_id}, instance_type: {instance_type}")

    # Load user-data script from an external file
    try:
        ud_path = config_file.parent / "ec2_user_data.sh"
        user_data = ud_path.read_text(encoding="utf-8")

        # Inject AUTO_SHUTDOWN environment variable (default: true)
        auto_shutdown = os.environ.get("AUTO_SHUTDOWN", "true").lower()
        if auto_shutdown not in ("true", "false"):
            auto_shutdown = "true"

        # Prepend export statement to user data script
        user_data = f"export AUTO_SHUTDOWN={auto_shutdown}\n{user_data}"
        logger.info(f"AUTO_SHUTDOWN set to: {auto_shutdown}")
    except Exception:
        logger.warning("ec2_user_data.sh not found, proceeding without user data")
        user_data = ""

    try:
        ec2_client = get_ec2_client(config, region)

        # Build block device mapping
        bdm: List[Dict[str, Any]] = []
        ebs_cfg = cfg.get("ebs", {}) or {}
        device_name = ebs_cfg.get("device_name", "/dev/xvda")
        snapshot_id = ebs_cfg.get("snapshot_id", None)
        volume_size = ebs_cfg.get("volume_size", 20)
        volume_type = ebs_cfg.get("volume_type", "gp3")
        iops = ebs_cfg.get("iops", 3000)
        throughput = ebs_cfg.get("throughput", 125)
        encrypted = ebs_cfg.get("encrypted", False)
        delete_on_termination = ebs_cfg.get("delete_on_termination", True)

        ebs: Dict[str, Any] = {
            "Encrypted": bool(encrypted),
            "DeleteOnTermination": bool(delete_on_termination),
            "Iops": iops,
            "VolumeSize": volume_size,
            "VolumeType": volume_type,
            "Throughput": throughput,
        }
        if snapshot_id:
            ebs["SnapshotId"] = snapshot_id

        bdm.append({"DeviceName": device_name, "Ebs": ebs})

        # Network config
        network_interfaces = None
        net_cfg = cfg.get("network", {}) or {}
        sg_list = net_cfg.get("security_group_ids", None)
        subnet_id = net_cfg.get("subnet_id", None)
        associate_pub = net_cfg.get("associate_public_ip", True)

        if sg_list:
            ni: Dict[str, Any] = {
                "AssociatePublicIpAddress": bool(associate_pub),
                "DeviceIndex": 0,
                "Groups": sg_list,
            }
            if subnet_id:
                ni["SubnetId"] = subnet_id
            network_interfaces = [ni]

        # Metadata and private DNS options
        md_cfg = cfg.get("metadata", {}) or {}
        metadata_opts = {
            "HttpEndpoint": md_cfg.get("http_endpoint", "enabled"),
            "HttpPutResponseHopLimit": md_cfg.get("http_put_response_hop_limit", 2),
            "HttpTokens": md_cfg.get("http_tokens", "required"),
        }

        pdns_cfg = cfg.get("private_dns", {}) or {}
        private_dns_opts = {
            "HostnameType": pdns_cfg.get("hostname_type", "ip-name"),
            "EnableResourceNameDnsARecord": pdns_cfg.get("enable_dns_a", True),
            "EnableResourceNameDnsAAAARecord": pdns_cfg.get("enable_dns_aaaa", False),
        }

        # Build tags
        tags_cfg = cfg.get("tags", None)
        if isinstance(tags_cfg, dict):
            tags_list = [{"Key": k, "Value": str(v)} for k, v in tags_cfg.items()]
        elif isinstance(tags_cfg, list):
            tags_list = tags_cfg
        else:
            tags_list = [
                {"Key": "Name", "Value": "nova-app-node-test"},
                {"Key": "Service", "Value": "sparsity-nova"},
            ]

        # Key pair and IAM instance profile
        key_name = cfg.get("key_name", None)
        iam_instance_profile_arn = cfg.get("iam_instance_profile_arn", None)

        run_kwargs: Dict[str, Any] = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "UserData": user_data,
            "BlockDeviceMappings": bdm,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": tags_list,
                }
            ],
            "EnclaveOptions": {"Enabled": cfg.get("enclave", {}).get("enabled", True)},
            "MetadataOptions": metadata_opts,
            "PrivateDnsNameOptions": private_dns_opts,
        }

        if key_name:
            run_kwargs["KeyName"] = key_name

        if iam_instance_profile_arn:
            run_kwargs["IamInstanceProfile"] = {"Arn": iam_instance_profile_arn}

        if network_interfaces is not None:
            run_kwargs["NetworkInterfaces"] = network_interfaces
        else:
            # Fallback: if security groups provided but not as network interfaces
            if sg_list:
                run_kwargs["SecurityGroupIds"] = sg_list
            if subnet_id:
                run_kwargs["SubnetId"] = subnet_id

        logger.debug("EC2 run_instances parameters: %s", run_kwargs)
        response = ec2_client.run_instances(**run_kwargs)

    except NoCredentialsError as e:
        logger.error("AWS credentials not configured: %s", e, exc_info=True)
        raise RuntimeError("No AWS credentials configured") from e
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code")
        msg = err.get("Message")
        logger.error("AWS ClientError: %s - %s", code, msg)
        raise RuntimeError(f"AWS ClientError: {code} - {msg}") from e
    except Exception as e:
        logger.error(f"Failed to launch EC2 instance: {e}", exc_info=True)
        raise

    instance_id = response['Instances'][0]['InstanceId']
    private_ip = response['Instances'][0].get('PrivateIpAddress', 'pending')
    logger.info(f"Successfully launched EC2 instance: {instance_id} (private_ip={private_ip})")

    # Try to determine CPU and RAM for the chosen instance type
    try:
        desc = ec2_client.describe_instance_types(InstanceTypes=[instance_type])
        its = desc.get("InstanceTypes", [])
        if its:
            info = its[0]
            vcpu_info = info.get("VCpuInfo", {})
            mem_info = info.get("MemoryInfo", {})
            cpu_total = int(vcpu_info.get("DefaultVCpus") or vcpu_info.get("DefaultVCpus", 0))
            ram_mib_total = int(mem_info.get("SizeInMiB") or 0)
        else:
            raise RuntimeError("No InstanceTypes returned")
        if cpu_total <= 0 or ram_mib_total <= 0:
            raise RuntimeError("Invalid instance type resources")
    except Exception:
        # Log and fall back to known defaults for common c6i sizes
        logger.warning(
            "Could not resolve instance type resources for %s; using fallback values",
            instance_type,
            exc_info=True
        )
        fallback = {
            "c6i.large": (2, 4096),
            "c6i.xlarge": (4, 8192),
            "c6i.2xlarge": (8, 16384),
            "c6i.4xlarge": (16, 32768),
            "c6i.8xlarge": (32, 65536),
            "c6i.12xlarge": (48, 98304),
            "c6i.16xlarge": (64, 131072),
        }
        cpu_total, ram_mib_total = fallback.get(instance_type, (8, 16384))

    return {
        "instance_id": instance_id,
        "region": region,
        "state": "idle",
        "cpu_total": cpu_total,
        "ram_mib_total": ram_mib_total,
        "cpu_free": cpu_total - 2,  # Reserve 2 CPUs for system
        "ram_mib_free": ram_mib_total - 2048,  # Reserve 2GB for system
        "private_ip": private_ip,
        "created_at": datetime.utcnow().isoformat(),
    }


def main():
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Provision EC2 instances with Nitro Enclaves for Nova Platform"
    )
    parser.add_argument(
        "--region",
        required=True,
        help="AWS region to provision in (e.g., us-west-1)"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to ec2.yaml config file (default: ec2.yaml in script directory)"
    )
    parser.add_argument(
        "--env",
        type=Path,
        help="Path to .env file for AWS credentials and settings"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine config file path
    if args.config:
        config_file = args.config
    else:
        config_file = Path(__file__).parent / "ec2.yaml"

    # Load environment config
    env_file = args.env
    if not env_file:
        # Try to find .env in parent directory (project root)
        parent_env = Path(__file__).parent.parent / ".env"
        if parent_env.exists():
            env_file = parent_env

    config = EC2ProvisionConfig(env_file)

    try:
        result = provision_ec2_instance(args.region, config, config_file)

        print("\n" + "=" * 60)
        print("EC2 Instance Provisioned Successfully!")
        print("=" * 60)
        print(f"Instance ID:   {result['instance_id']}")
        print(f"Region:        {result['region']}")
        print(f"Private IP:    {result['private_ip']}")
        print(f"CPU Total:     {result['cpu_total']} vCPUs")
        print(f"RAM Total:     {result['ram_mib_total']} MiB")
        print(f"CPU Free:      {result['cpu_free']} vCPUs")
        print(f"RAM Free:      {result['ram_mib_free']} MiB")
        print(f"Created At:    {result['created_at']}")
        print("=" * 60)

        return 0

    except Exception as e:
        logger.error(f"Failed to provision EC2 instance: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
