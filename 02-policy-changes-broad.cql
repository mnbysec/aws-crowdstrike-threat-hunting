# Query 02 - Policy Changes (Broad IAM + S3)
# Purpose: Detects any Put*Policy across IAM and S3.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^(iam|s3)\.amazonaws\.com$/i
Vendor.eventName=/^Put.*Policy$/i
#event.outcome=/^success$/i
| select([@timestamp, Vendor.eventSource, Vendor.eventName, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)