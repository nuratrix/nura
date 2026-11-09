"""Cost Explorer tools for the Strands cost agent. Costs are for the current AWS account."""
from datetime import date, timedelta

import os
from functools import cached_property

import boto3
from strands import tool


class _Ce:
    """Lazy Cost Explorer client so AWS_PROFILE from .env is honored."""

    @cached_property
    def client(self):
        # Cost Explorer is a global service served from us-east-1.
        session = boto3.Session(profile_name=os.getenv("AWS_PROFILE") or None)
        return session.client("ce", region_name="us-east-1")

    def __getattr__(self, name):
        return getattr(self.client, name)


_ce = _Ce()

# Service names as they appear in Cost Explorer.
SERVICES = {
    "ec2": ["Amazon Elastic Compute Cloud - Compute", "EC2 - Other"],
    "rds": ["Amazon Relational Database Service"],
    "s3": ["Amazon Simple Storage Service"],
}


def _period(days: int) -> dict:
    end = date.today()
    return {"Start": (end - timedelta(days=days)).isoformat(), "End": end.isoformat()}


def _service_cost(services: list[str], days: int, extra_filter: dict | None = None) -> dict:
    flt = {"Dimensions": {"Key": "SERVICE", "Values": services}}
    if extra_filter:
        flt = {"And": [flt, extra_filter]}
    resp = _ce.get_cost_and_usage(
        TimePeriod=_period(days),
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        Filter=flt,
    )
    total = sum(float(r["Total"]["UnblendedCost"]["Amount"]) for r in resp["ResultsByTime"])
    return {"days": days, "total_usd": round(total, 2)}


@tool
def get_ec2_cost(days: int = 30) -> dict:
    """Get EC2 cost (compute and EC2-other such as EBS/data transfer) for the last N days.

    Args:
        days: Number of days to look back (default 30).
    """
    return _service_cost(SERVICES["ec2"], days)


@tool
def get_rds_cost(days: int = 30) -> dict:
    """Get RDS cost for the last N days.

    Args:
        days: Number of days to look back (default 30).
    """
    return _service_cost(SERVICES["rds"], days)


@tool
def get_s3_cost(days: int = 30) -> dict:
    """Get S3 cost for the last N days.

    Args:
        days: Number of days to look back (default 30).
    """
    return _service_cost(SERVICES["s3"], days)


@tool
def get_reservation_cost(days: int = 30) -> dict:
    """Get cost of Reserved Instance / Savings Plan fees for the last N days, by service.

    Args:
        days: Number of days to look back (default 30).
    """
    resp = _ce.get_cost_and_usage(
        TimePeriod=_period(days),
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        Filter={"Dimensions": {
            "Key": "RECORD_TYPE",
            "Values": ["Fee", "RIFee", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee"],
        }},
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    by_service: dict[str, float] = {}
    for r in resp["ResultsByTime"]:
        for g in r["Groups"]:
            by_service[g["Keys"][0]] = by_service.get(g["Keys"][0], 0) + float(
                g["Metrics"]["UnblendedCost"]["Amount"]
            )
    return {"days": days, "by_service_usd": {k: round(v, 2) for k, v in by_service.items()}}


@tool
def get_reservation_utilization(days: int = 30) -> dict:
    """Get Reserved Instance utilization percentage for the last N days.

    Args:
        days: Number of days to look back (default 30).
    """
    try:
        resp = _ce.get_reservation_utilization(TimePeriod=_period(days))
    except _ce.exceptions.DataUnavailableException:
        return {"message": "No reservation data for this account."}
    return {"days": days, "utilization_percentage": resp["Total"].get("UtilizationPercentage")}


COST_TOOLS = [get_ec2_cost, get_rds_cost, get_s3_cost, get_reservation_cost, get_reservation_utilization]
