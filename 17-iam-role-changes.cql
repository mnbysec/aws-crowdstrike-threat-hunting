# Query 17 - IAM Role Created or Updated
# Purpose: Detect creation or modification of IAM roles.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^iam\.amazonaws\.com$/i
Vendor.eventName=/^(CreateRole|UpdateAssumeRolePolicy)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.requestParameters])
| sort(@timestamp, order=desc, limit=50)