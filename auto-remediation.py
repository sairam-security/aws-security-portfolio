import boto3
from datetime import datetime

# Credentials loaded from
# C:\Users\sai\.aws\credentials

ec2 = boto3.client('ec2', region_name='us-east-2')

print("=" * 55)
print("AUTO REMEDIATION BOT")
print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
print("=" * 55)

DANGEROUS_PORTS = [22, 3389, 3306, 5432, 8080]
OPEN_CIDR = ['0.0.0.0/0', '::/0']

fixed_count = 0
scan_count = 0

groups = ec2.describe_security_groups()['SecurityGroups']
print(f"\nScanning {len(groups)} security groups...\n")

for group in groups:
    group_id = group['GroupId']
    group_name = group['GroupName']
    scan_count += 1

    for rule in group['IpPermissions']:
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)

        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')

            if cidr in OPEN_CIDR:
                if from_port in DANGEROUS_PORTS:
                    print(f"DANGEROUS RULE FOUND")
                    print(f"Group  : {group_name} ({group_id})")
                    print(f"Port   : {from_port}")
                    print(f"Source : {cidr}")
                    print(f"Action : Removing rule...")

                    try:
                        ec2.revoke_security_group_ingress(
                            GroupId=group_id,
                            IpPermissions=[{
                                'IpProtocol': rule['IpProtocol'],
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpRanges': [{'CidrIp': cidr}]
                            }]
                        )
                        print(f"FIXED - Rule removed successfully")
                        fixed_count += 1

                    except Exception as e:
                        print(f"Could not fix: {e}")

                else:
                    print(f"Open rule detected (low risk)")
                    print(f"Group : {group_name}")
                    print(f"Port  : {from_port}")

print("\n" + "=" * 55)
print(f"SCAN COMPLETE")
print(f"Groups scanned : {scan_count}")
print(f"Rules fixed    : {fixed_count}")
print(f"Time           : {datetime.now().strftime('%H:%M:%S')}")
print("=" * 55)