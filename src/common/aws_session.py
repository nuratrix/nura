"""boto3 sessions for the account a finding belongs to.

The agents run in the governance account; findings belong to member accounts.
A finding in the governance account itself (or any account when MEMBER_ROLE_NAME is
empty, e.g. local single-account runs) uses the default credentials.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import boto3

_CACHE: dict[str, dict] = {}   # account_id -> STS credentials


def base_session(region: str | None = None) -> boto3.Session:
    return boto3.Session(profile_name=os.getenv("AWS_PROFILE") or None,
                         region_name=region or os.getenv("AWS_REGION", "us-east-1"))


@lru_cache(maxsize=1)
def _own_account() -> str:
    return base_session().client("sts").get_caller_identity()["Account"]


def session_for(account_id: str, region: str) -> boto3.Session:
    """Read-only session in account_id/region, assuming MEMBER_ROLE_NAME when it's another account."""
    role = os.getenv("MEMBER_ROLE_NAME", "governance-platform-reader")
    if not role or account_id == _own_account():
        return base_session(region)

    creds = _CACHE.get(account_id)
    if not creds or datetime.now(timezone.utc) >= creds["Expiration"] - timedelta(minutes=5):
        creds = base_session().client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
            RoleSessionName=f"nura-judgment-{account_id}",
            ExternalId=os.getenv("MEMBER_ROLE_EXTERNAL_ID", "governance-platform"),
            DurationSeconds=3600,
        )["Credentials"]
        _CACHE[account_id] = creds
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                         aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"], region_name=region)
