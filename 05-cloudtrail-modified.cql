# Query 05 - CloudTrail Disabled or Modified
# Purpose: Detect tampering with CloudTrail logs.
# Severity: Critical

#Vendor="aws"
Vendor.eventSource=/^cloudtrail\.amazonaws\.com$/i
Vendor.eventName=/^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)