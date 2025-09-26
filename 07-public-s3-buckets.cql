# Query 07 - Public S3 Bucket Exposure
# Purpose: Detect S3 buckets made public via ACL/Policy.
# Severity: High

#Vendor="aws"
Vendor.eventSource=/^s3\.amazonaws\.com$/i
Vendor.eventName=/^(PutBucketAcl|PutBucketPolicy)$/i
#event.outcome=/^success$/i
| Vendor.requestParameters=/AllUsers|AuthenticatedUsers/i
| select([@timestamp, Vendor.eventName, Vendor.requestParameters, Vendor.userIdentity.arn, Vendor.sourceIPAddress])
| sort(@timestamp, order=desc, limit=50)