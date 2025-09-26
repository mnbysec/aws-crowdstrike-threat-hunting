# AWS CrowdStrike Threat Hunting Queries

This repository contains **20 high-value AWS threat hunting queries** for use in CrowdStrike Falcon (CQL).  
Each query is saved as a `.cql` file under `queries/`.

## 📂 Categories
- Identity & Access (Inline policies, Root usage, MFA, IAM roles/users)
- Logging & Monitoring (CloudTrail, GuardDuty, AWS Config)
- Data Security (S3 public buckets, RDS snapshots, KMS policies)
- Network & Infrastructure (Security Groups, EC2 launches)
- Reconnaissance (List APIs, unusual region use, STS AssumeRole)

## 🚀 Usage
1. Copy queries into Falcon Investigate > Advanced Event Search.
2. Save queries for repeat use.
3. Wrap with `| test(count(...) > 0)` to create Fusion Correlation Rules.

## ⚠️ Notes
- Queries use anchored regex (`^...$`) where applicable.
- Tune with exclusions (trusted roles, accounts) to reduce noise.