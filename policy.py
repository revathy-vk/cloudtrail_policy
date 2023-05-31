import boto3
import json
import re
from datetime import datetime, timedelta

def get_unique_cloudtrail_events(username, days):
    # Create a Boto3 client for CloudTrail
    client = boto3.client('cloudtrail')
    
    # Calculate the start and end time for the past 'days' days
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    # Retrieve CloudTrail events
    response = client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'Username', 'AttributeValue': username}
        ],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=100  # Adjust the number of results as per your requirement
    )
    
    # Extract unique service:action combinations
    unique_events = set()
    for event in response['Events']:
        unique_events.add(f"{event['EventSource']}:{event['EventName']}")
    
    return list(unique_events)

username = 'terraform-cloud'
days = 90

unique_events = get_unique_cloudtrail_events(username, days)
print(unique_events)

output_list = []

for event in unique_events:
    event_source, event_name = event.split(':')
    
    # Extract string before the first dot in event source
    event_source = event_source.split('.')[0]
    
    # Extract string before the second capital letter in event name
    matches = re.findall(r'[A-Z][a-z]*', event_name)
    result = ''.join(matches[:1])
    
    event_name = result + '*'
    
    modified_event = event_source + ':' + event_name
    output_list.append(modified_event)

print(output_list)
unique_list = list(set(output_list))
print(unique_list)

policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": unique_list,
            "Resource": "*"
        }
    ]
}

# Save policy as JSON file
with open('policy.json', 'w') as file:
    json.dump(policy_document, file, indent=4)

print("IAM policy created and saved as 'policy.json'")