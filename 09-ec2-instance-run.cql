# Query 09 - EC2 Instance Creation
# Purpose: Detect launching of new EC2 instances.
# Severity: Medium

#Vendor="aws"
Vendor.eventSource=/^ec2\.amazonaws\.com$/i
Vendor.eventName=/^RunInstances$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.requestParameters])
| sort(@timestamp, order=desc, limit=50)