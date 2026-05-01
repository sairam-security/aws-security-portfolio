import boto3
from datetime import datetime, timezone

# Credentials loaded from C:\Users\sai\.aws\credentials

iam = boto3.client('iam', region_name='us-east-2')

print("=" * 55)
print("IAM SECURITY AUDIT REPORT")
print("=" * 55)

users = iam.list_users()['Users']
print(f"\nTotal Users: {len(users)}\n")

for user in users:
    username = user['UserName']
    print(f"\nUser: {username}")
    print("-" * 40)

    mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
    if mfa:
        print(f"  MFA Status   : ENABLED")
    else:
        print(f"  MFA Status   : NOT ENABLED - HIGH RISK")

    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    if keys:
        for key in keys:
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            if age > 90:
                print(f"  Access Key   : {key['AccessKeyId']}")
                print(f"  Status       : {key['Status']}")
                print(f"  Age          : {age} days - ROTATE NOW")
            else:
                print(f"  Access Key   : {key['AccessKeyId']}")
                print(f"  Status       : {key['Status']}")
                print(f"  Age          : {age} days - OK")
    else:
        print(f"  Access Key   : None")

    policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    for policy in policies:
        if 'Admin' in policy['PolicyName']:
            print(f"  Permission   : {policy['PolicyName']} - ADMIN ACCESS")
        else:
            print(f"  Permission   : {policy['PolicyName']}")

print("\n" + "=" * 55)
print("AUDIT COMPLETE")
print("=" * 55)