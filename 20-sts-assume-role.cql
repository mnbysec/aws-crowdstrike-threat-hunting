# Query 20 - STS AssumeRole
# Purpose: Detect use of STS AssumeRole (possible token abuse).
# Severity: Medium

#Vendor="aws"
Vendor.eventSource=/^sts\.amazonaws\.com$/i
Vendor.eventName=/^AssumeRole$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.requestParameters])
| sort(@timestamp, order=desc, limit=50)