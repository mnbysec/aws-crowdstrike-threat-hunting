# Query 10 - Sensitive API Discovery
# Purpose: Detect reconnaissance calls like ListUsers, ListSecrets.
# Severity: Medium

#Vendor="aws"
Vendor.eventName=/^(ListUsers|ListPolicies|ListAccessKeys|DescribeSecurityGroups|ListSecrets)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventSource, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)