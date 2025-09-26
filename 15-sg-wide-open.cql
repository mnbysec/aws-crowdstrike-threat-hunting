# Query 15 - Security Group Wide Open
# Purpose: Detect changes opening access to 0.0.0.0/0.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^ec2\.amazonaws\.com$/i
Vendor.eventName=/^(AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress)$/i
#event.outcome=/^success$/i
| Vendor.requestParameters=/0\.0\.0\.0\/0/i
| select([@timestamp, Vendor.eventName, Vendor.requestParameters, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)