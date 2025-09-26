# Query 12 - IAM User Created
# Purpose: Detect unexpected IAM user creation.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^iam\.amazonaws\.com$/i
Vendor.eventName=/^CreateUser$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.requestParameters])
| sort(@timestamp, order=desc, limit=50)