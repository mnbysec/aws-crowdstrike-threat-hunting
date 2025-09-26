# Query 13 - Console Login Without MFA
# Purpose: Detect console logins that bypass MFA.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^signin\.amazonaws\.com$/i
Vendor.eventName=/^ConsoleLogin$/i
#event.outcome=/^success$/i
| Vendor.additionalEventData.MFAUsed=/^No$/i
| select([@timestamp, Vendor.userIdentity.arn, Vendor.sourceIPAddress, Vendor.awsRegion, Vendor.additionalEventData.MFAUsed])
| sort(@timestamp, order=desc, limit=50)