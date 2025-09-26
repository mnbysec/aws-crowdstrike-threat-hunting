# Query 06 - Access Key Creation
# Purpose: Detect creation of IAM access keys.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^iam\.amazonaws\.com$/i
Vendor.eventName=/^CreateAccessKey$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.userIdentity.arn, Vendor.eventName, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)