# Query 19 - RDS Snapshot Shared Publicly
# Purpose: Detect sharing of RDS snapshots with 'all'.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^rds\.amazonaws\.com$/i
Vendor.eventName=/^(ModifyDBSnapshotAttribute|ModifyDBClusterSnapshotAttribute)$/i
#event.outcome=/^success$/i
| Vendor.requestParameters=/all/i
| select([@timestamp, Vendor.eventName, Vendor.requestParameters, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)