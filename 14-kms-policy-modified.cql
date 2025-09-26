# Query 14 - KMS Policy Modified
# Purpose: Detect changes to KMS key policies.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^kms\.amazonaws\.com$/i
Vendor.eventName=/^(PutKeyPolicy|UpdateKeyDescription)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)