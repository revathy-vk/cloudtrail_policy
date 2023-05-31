import boto3
import json
import re
from datetime import datetime, timedelta

def get_unique_events(username, days):
    # Create a Boto3 client for CloudTrail
    client = boto3.client('cloudtrail')
    
    # Calculate the start and end dates for the time range
    end_time = datetime.now()
    start_time = end_time - timedelta(days=days)
    
    # Initialize variables
    events = []
    next_token = None
    
    # Retrieve CloudTrail events
    while True:
        if next_token:
            response = client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'Username', 'AttributeValue': username}
                ],
                StartTime=start_time,
                EndTime=end_time,
                NextToken=next_token
            )
        else:
            response = client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'Username', 'AttributeValue': username}
                ],
                StartTime=start_time,
                EndTime=end_time
            )
        
        # Process events
        for event in response['Events']:
            events.append(f"{event['EventSource']}:{event['EventName']}")
        
        # Check if there are more events
        if 'NextToken' in response:
            next_token = response['NextToken']
        else:
            break
    
    return events

# Usage example
username = 'terraform-cloud'
days = 10

unique_events = get_unique_events(username, days)
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