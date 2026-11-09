"""The finding the orchestrator is judging, as seen by context tools.

synthesize.py calls each agent with invocation_state={"finding": finding}. Tools declared
with @tool(context=True) read it from tool_context, so the resource, account and region
come from the stored finding, never from the LLM. The model can't point a tool at a
different resource.
"""
from __future__ import annotations

from strands import ToolContext

from common.aws_session import session_for


class NoFindingContext(RuntimeError):
    pass


def current_finding(tool_context: ToolContext) -> dict:
    finding = (tool_context.invocation_state or {}).get("finding")
    if not finding:
        raise NoFindingContext("no finding in invocation_state; call the agent with "
                               "invocation_state={'finding': finding}")
    return finding


def finding_session(finding: dict):
    return session_for(finding["account_id"], finding["region"])


def resource_arn(finding: dict) -> str | None:
    """Best-effort ARN for the finding's resource; None when the type has no taggable ARN."""
    rid, rtype = finding["resource_id"], finding["resource_type"]
    if rid.startswith("arn:"):
        return rid
    acct, region = finding["account_id"], finding["region"]
    templates = {
        "AWS::EC2::Instance": "arn:aws:ec2:{r}:{a}:instance/{id}",
        "AWS::EC2::Volume": "arn:aws:ec2:{r}:{a}:volume/{id}",
        "AWS::EC2::Snapshot": "arn:aws:ec2:{r}::snapshot/{id}",
        "AWS::EC2::Image": "arn:aws:ec2:{r}::image/{id}",
        "AWS::EC2::SecurityGroup": "arn:aws:ec2:{r}:{a}:security-group/{id}",
        "AWS::EC2::VPC": "arn:aws:ec2:{r}:{a}:vpc/{id}",
        "AWS::EC2::Subnet": "arn:aws:ec2:{r}:{a}:subnet/{id}",
        "AWS::EC2::EIP": "arn:aws:ec2:{r}:{a}:elastic-ip/{id}",
        "AWS::EC2::NatGateway": "arn:aws:ec2:{r}:{a}:natgateway/{id}",
        "AWS::EC2::InternetGateway": "arn:aws:ec2:{r}:{a}:internet-gateway/{id}",
        "AWS::EC2::NetworkAcl": "arn:aws:ec2:{r}:{a}:network-acl/{id}",
        "AWS::EC2::TransitGateway": "arn:aws:ec2:{r}:{a}:transit-gateway/{id}",
        "AWS::EC2::VPCPeeringConnection": "arn:aws:ec2:{r}:{a}:vpc-peering-connection/{id}",
        "AWS::RDS::DBInstance": "arn:aws:rds:{r}:{a}:db:{id}",
        "AWS::RDS::DBCluster": "arn:aws:rds:{r}:{a}:cluster:{id}",
        "AWS::RDS::DBSnapshot": "arn:aws:rds:{r}:{a}:snapshot:{id}",
        "AWS::S3::Bucket": "arn:aws:s3:::{id}",
        "AWS::Lambda::Function": "arn:aws:lambda:{r}:{a}:function:{id}",
        "AWS::EKS::Cluster": "arn:aws:eks:{r}:{a}:cluster/{id}",
        "AWS::ECR::Repository": "arn:aws:ecr:{r}:{a}:repository/{id}",
        "AWS::KMS::Key": "arn:aws:kms:{r}:{a}:key/{id}",
        "AWS::Logs::LogGroup": "arn:aws:logs:{r}:{a}:log-group:{id}",
        "AWS::IAM::User": "arn:aws:iam::{a}:user/{id}",
        "AWS::IAM::Role": "arn:aws:iam::{a}:role/{id}",
        "AWS::CloudTrail::Trail": "arn:aws:cloudtrail:{r}:{a}:trail/{id}",
        "AWS::Backup::BackupVault": "arn:aws:backup:{r}:{a}:backup-vault:{id}",
    }
    tpl = templates.get(rtype)
    return tpl.format(r=region, a=acct, id=rid) if tpl else None
