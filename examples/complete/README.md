# Complete example

This example deploys the S3 scanning pipeline with a VPC-hosted, internet-facing Transfer Family SFTP server. Provide a VPC, public subnets, one Elastic IP allocation ID per subnet, approved client CIDRs, and users with disjoint logical home prefixes; ancestor/descendant prefixes are rejected.

Subscribe downstream consumers to the module's `sns_topic_arn` output. Set `sftp_custom_hostname` to use a branded endpoint name and set `sftp_route53_hosted_zone_id` to create its Route 53 CNAME.
