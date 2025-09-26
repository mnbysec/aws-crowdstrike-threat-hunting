# Query 03 - Attach or Create Policies
# Purpose: Detect privilege escalation attempts by attaching or creating policies.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^iam\.amazonaws\.com$/i
Vendor.eventName=/^(AttachUserPolicy|AttachGroupPolicy|AttachRolePolicy|CreatePolicy)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)