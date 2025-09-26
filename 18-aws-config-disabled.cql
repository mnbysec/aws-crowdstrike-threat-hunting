# Query 18 - AWS Config Disabled
# Purpose: Detect disabling of AWS Config monitoring.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^config\.amazonaws\.com$/i
Vendor.eventName=/^(StopConfigurationRecorder|DeleteConfigurationRecorder)$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)