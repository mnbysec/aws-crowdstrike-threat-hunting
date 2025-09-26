# Query 01 - Inline User Policies
# Purpose: Detects use of PutUserPolicy (inline policy directly attached to user)
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^iam\.amazonaws\.com$/i
Vendor.eventName=/^PutUserPolicy$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventSource, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.requestParameters])
| sort(@timestamp, order=desc, limit=50)