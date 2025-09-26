# Query 08 - Unusual AWS Region Usage
# Purpose: Detect activity in AWS regions outside the norm.
# Severity: Medium

#Vendor="aws"
#event.outcome=/^success$/i
| groupBy([Vendor.awsRegion, Vendor.userIdentity.arn], function=(count(Vendor.eventName, as=events)))
| sort(events, order=desc)