# Query 04 - Root Account Usage
# Purpose: Detect root account activity (should be zero).
# Severity: Critical

#Vendor="aws"
Vendor.userIdentity.type=/^Root$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventName, Vendor.sourceIPAddress, Vendor.awsRegion])
| sort(@timestamp, order=desc, limit=50)