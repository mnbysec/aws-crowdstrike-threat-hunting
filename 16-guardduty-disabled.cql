# Query 16 - GuardDuty Disabled
# Purpose: Detect attempts to disable GuardDuty.
# Severity: Critical

#Vendor="aws"
Vendor.eventSource=/^guardduty\.amazonaws\.com$/i
Vendor.eventName=/^(DeleteDetector|StopMonitoringMembers)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)