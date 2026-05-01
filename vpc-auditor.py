import boto3

# Credentials loaded from
# C:\Users\sai\.aws\credentials

ec2 = boto3.client('ec2', region_name='us-east-2')

print("=" * 55)
print("VPC SECURITY AUDIT REPORT")
print("=" * 55)

# Check 1 - Subnet public IP settings
print("\nSUBNET AUDIT")
print("-" * 55)
subnets = ec2.describe_subnets()['Subnets']

for subnet in subnets:
    name = "unnamed"
    for tag in subnet.get('Tags', []):
        if tag['Key'] == 'Name':
            name = tag['Value']
    auto_public = subnet.get('MapPublicIpOnLaunch', False)
    cidr = subnet['CidrBlock']
    if auto_public:
        print(f"  PUBLIC  : {name} ({cidr}) - Auto public IP ON")
    else:
        print(f"  PRIVATE : {name} ({cidr}) - Auto public IP OFF")

# Check 2 - Security groups open to internet
print("\nSECURITY GROUP AUDIT")
print("-" * 55)
groups = ec2.describe_security_groups()['SecurityGroups']

for group in groups:
    for rule in group['IpPermissions']:
        for ip in rule.get('IpRanges', []):
            if ip.get('CidrIp') == '0.0.0.0/0':
                port = rule.get('FromPort', 'ALL')
                print(f"  OPEN : {group['GroupName']} - Port {port} open to internet")

# Check 3 - EC2 instances with public IPs
print("\nEC2 PUBLIC IP AUDIT")
print("-" * 55)
reservations = ec2.describe_instances()['Reservations']

for res in reservations:
    for instance in res['Instances']:
        name = "unnamed"
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                name = tag['Value']
        public_ip = instance.get('PublicIpAddress', None)
        state = instance['State']['Name']
        if public_ip:
            print(f"  PUBLIC  : {name} - IP: {public_ip} ({state})")
        else:
            print(f"  PRIVATE : {name} - No public IP ({state})")

# Check 4 - Internet Gateways
print("\nINTERNET GATEWAY AUDIT")
print("-" * 55)
igws = ec2.describe_internet_gateways()['InternetGateways']

for igw in igws:
    igw_id = igw['InternetGatewayId']
    attachments = igw['Attachments']
    if attachments:
        vpc_id = attachments[0]['VpcId']
        print(f"  IGW : {igw_id} attached to {vpc_id}")
    else:
        print(f"  IGW : {igw_id} - Not attached to any VPC")

# Check 5 - Network ACLs
print("\nNETWORK ACL AUDIT")
print("-" * 55)
nacls = ec2.describe_network_acls()['NetworkAcls']

for nacl in nacls:
    nacl_id = nacl['NetworkAclId']
    is_default = nacl['IsDefault']
    associations = len(nacl['Associations'])
    print(f"  NACL : {nacl_id} - Default: {is_default} - Subnets: {associations}")

print("\n" + "=" * 55)
print("AUDIT COMPLETE")
print("=" * 55)

