import boto3
from datetime import datetime, timezone

# Credentials loaded from
# C:\Users\sai\.aws\credentials

ec2 = boto3.client('ec2', region_name='us-east-2')
iam = boto3.client('iam', region_name='us-east-2')
s3 = boto3.client('s3', region_name='us-east-2')
sts = boto3.client('sts', region_name='us-east-2')

report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
report_date = datetime.now().strftime('%Y-%m-%d')
account_id = sts.get_caller_identity()['Account']

print("Generating security report...")

# IAM Check
users = iam.list_users()['Users']
iam_issues = []

for user in users:
    username = user['UserName']
    mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
    if not mfa:
        iam_issues.append(f"  {username} - MFA not enabled")

    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        age = (datetime.now(timezone.utc) - key['CreateDate']).days
        if age > 90:
            iam_issues.append(f"  {username} - Access key {age} days old")

# Security Group Check
groups = ec2.describe_security_groups()['SecurityGroups']
sg_issues = []
DANGEROUS_PORTS = [22, 3389, 3306, 5432]

for group in groups:
    for rule in group['IpPermissions']:
        from_port = rule.get('FromPort', 0)
        for ip in rule.get('IpRanges', []):
            if ip.get('CidrIp') == '0.0.0.0/0':
                if from_port in DANGEROUS_PORTS:
                    sg_issues.append(
                        f"  {group['GroupName']} - Port {from_port} open to internet"
                    )

# S3 Check
buckets = s3.list_buckets()['Buckets']
s3_issues = []

for bucket in buckets:
    name = bucket['Name']
    try:
        pab = s3.get_public_access_block(Bucket=name)
        config = pab['PublicAccessBlockConfiguration']
        if not all(config.values()):
            s3_issues.append(f"  {name} - Public access not blocked")
    except Exception:
        s3_issues.append(f"  {name} - No public access block configured")

# EC2 Check
reservations = ec2.describe_instances()['Reservations']
ec2_issues = []

for res in reservations:
    for instance in res['Instances']:
        name = "unnamed"
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                name = tag['Value']
        state = instance['State']['Name']
        public_ip = instance.get('PublicIpAddress')
        if public_ip and state == 'running':
            ec2_issues.append(
                f"  {name} - Running with public IP: {public_ip}"
            )

# Build Report
report = f"""
AWS SECURITY REPORT
Generated : {report_time}
Account   : {account_id}
Region    : us-east-2

--------------------------------------------------
1. IAM SECURITY
--------------------------------------------------
Total Users  : {len(users)}
Issues Found : {len(iam_issues)}

{chr(10).join(iam_issues) if iam_issues else '  All IAM checks passed'}

--------------------------------------------------
2. SECURITY GROUPS
--------------------------------------------------
Total Groups : {len(groups)}
Issues Found : {len(sg_issues)}

{chr(10).join(sg_issues) if sg_issues else '  All security groups properly configured'}

--------------------------------------------------
3. S3 BUCKET SECURITY
--------------------------------------------------
Total Buckets : {len(buckets)}
Issues Found  : {len(s3_issues)}

{chr(10).join(s3_issues) if s3_issues else '  All S3 buckets secured'}

--------------------------------------------------
4. EC2 INSTANCES
--------------------------------------------------
Issues Found : {len(ec2_issues)}

{chr(10).join(ec2_issues) if ec2_issues else '  No running instances with public IPs'}

--------------------------------------------------
SUMMARY
--------------------------------------------------
Total Issues : {len(iam_issues) + len(sg_issues) + len(s3_issues) + len(ec2_issues)}
IAM Issues   : {len(iam_issues)}
SG Issues    : {len(sg_issues)}
S3 Issues    : {len(s3_issues)}
EC2 Issues   : {len(ec2_issues)}

Report saved : security-report-{report_date}.txt
--------------------------------------------------
"""

print(report)

filename = f"security-report-{report_date}.txt"
with open(f"C:\\.aws\\{filename}", 'w', encoding='utf-8') as f:
    f.write(report)

print(f"Report saved: C:\\.aws\\{filename}")