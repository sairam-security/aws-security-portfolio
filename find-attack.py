import boto3
from datetime import datetime, timezone, timedelta

# Credentials loaded from
# C:\Users\sai\.aws\credentials

print("=" * 55)
print("ATTACK EVIDENCE FINDER")
print("=" * 55)

regions = ['us-east-1', 'us-east-2']

suspicious_events = [
    'CreateUser',
    'AttachUserPolicy',
    'CreateAccessKey',
    'DeleteUser',
    'DetachUserPolicy',
    'ListBuckets',
    'DeleteObject',
    'DeleteObjects',
    'PutUserPolicy'
]

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=24)

for region in regions:
    print(f"\nSearching region: {region}")
    print("=" * 55)

    cloudtrail = boto3.client(
        'cloudtrail',
        region_name=region
    )

    for event_name in suspicious_events:
        print(f"\nSearching: {event_name}")
        print("-" * 40)

        try:
            response = cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )

            events = response['Events']

            if events:
                for event in events:
                    print(f"  FOUND")
                    print(f"  Time  : {event['EventTime']}")
                    print(f"  User  : {event.get('Username', 'Unknown')}")
                    print(f"  Event : {event['EventName']}")
            else:
                print(f"  Not found")

        except Exception as e:
            print(f"  Error: {e}")

print("\n" + "=" * 55)
print("SEARCH COMPLETE")
print("=" * 55)