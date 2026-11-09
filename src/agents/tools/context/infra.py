"""Infrastructure context: the resource's lifecycle state and what depends on it.

The infra rules recommend cleanups (TERMINATE, DELETE, DELETE_SNAPSHOT) and flag risky
configuration. Before a cleanup goes ahead the agent needs to know: does the resource still
exist, how long has it been idle, and does anything still reference it (an AMI built on a
snapshot, a route table using a NAT gateway, AWS Backup owning a snapshot). Read-only; the
resource comes from the finding under review.
"""
from __future__ import annotations

import re

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, call, days_since, iso, ok, result
from agents.tools.context.finding_context import current_finding, finding_session

BACKUP_TAG = "aws:backup:source-resource"


def _stopped_days(reason: str | None) -> int | None:
    """EC2 StateTransitionReason looks like 'User initiated (2026-01-02 10:11:12 GMT)'."""
    m = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)", reason or "")
    return days_since(m.group(1).replace(" ", "T") + "+00:00") if m else None


def _tags(item: dict) -> dict:
    return {t["Key"]: t["Value"] for t in item.get("Tags", []) or []}


def _ec2_instance(f, ec2, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeInstances", ec2.describe_instances, InstanceIds=[rid],
                absent=("InvalidInstanceID.NotFound",))
    inst = next((i for r in ok(resp).get("Reservations", []) for i in r.get("Instances", [])), None)
    if not inst:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    tags = _tags(inst)
    prot = call(errors, "DescribeInstanceAttribute", ec2.describe_instance_attribute,
                InstanceId=rid, Attribute="disableApiTermination")
    state = inst.get("State", {}).get("Name")
    return result(f, errors, exists=True, state=state, instance_type=inst.get("InstanceType"),
                  launched_days_ago=days_since(inst.get("LaunchTime")),
                  stopped_days=_stopped_days(inst.get("StateTransitionReason")) if state == "stopped" else None,
                  state_reason=inst.get("StateTransitionReason"),
                  volumes=[m["Ebs"]["VolumeId"] for m in inst.get("BlockDeviceMappings", []) if "Ebs" in m],
                  auto_scaling_group=tags.get("aws:autoscaling:groupName"),
                  cloudformation_stack=tags.get("aws:cloudformation:stack-name"),
                  termination_protection=ok(prot).get("DisableApiTermination", {}).get("Value") if prot else None)


def _volume(f, ec2, errors):
    resp = call(errors, "DescribeVolumes", ec2.describe_volumes, VolumeIds=[f["resource_id"]],
                absent=("InvalidVolume.NotFound",))
    v = next(iter(ok(resp).get("Volumes", [])), None)
    if not v:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    return result(f, errors, exists=True, state=v.get("State"), size_gb=v.get("Size"), volume_type=v.get("VolumeType"),
                  encrypted=v.get("Encrypted"), created_days_ago=days_since(v.get("CreateTime")),
                  attached_to=[a.get("InstanceId") for a in v.get("Attachments", [])],
                  from_snapshot=v.get("SnapshotId") or None,
                  cloudformation_stack=_tags(v).get("aws:cloudformation:stack-name"))


def _snapshot(f, ec2, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeSnapshots", ec2.describe_snapshots, SnapshotIds=[rid],
                absent=("InvalidSnapshot.NotFound",))
    snap = next(iter(ok(resp).get("Snapshots", [])), None)
    if not snap:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    amis = call(errors, "DescribeImages", ec2.describe_images, Owners=["self"],
                Filters=[{"Name": "block-device-mapping.snapshot-id", "Values": [rid]}])
    vol = call(errors, "DescribeVolumes", ec2.describe_volumes, VolumeIds=[snap["VolumeId"]],
               absent=("InvalidVolume.NotFound", "InvalidParameterValue")) if snap.get("VolumeId") else ABSENT
    tags = _tags(snap)
    return result(f, errors, exists=True, age_days=days_since(snap.get("StartTime")), size_gb=snap.get("VolumeSize"),
                  encrypted=snap.get("Encrypted"), storage_tier=snap.get("StorageTier"),
                  description=(snap.get("Description") or "")[:120],
                  used_by_amis=None if amis is None else [i["ImageId"] for i in amis.get("Images", [])],
                  source_volume_exists=None if vol is None else vol is not ABSENT and bool(ok(vol).get("Volumes")),
                  managed_by_aws_backup=BACKUP_TAG in tags or "AWS Backup" in (snap.get("Description") or ""),
                  created_by_dlm="aws:dlm:lifecycle-policy-id" in tags)


def _image(f, ec2, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeImages", ec2.describe_images, ImageIds=[rid], absent=("InvalidAMIID.NotFound",))
    img = next(iter(ok(resp).get("Images", [])), None)
    if not img:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    perms = call(errors, "DescribeImageAttribute", ec2.describe_image_attribute, ImageId=rid,
                 Attribute="launchPermission")
    lp = ok(perms).get("LaunchPermissions", [])
    users = call(errors, "DescribeInstances", ec2.describe_instances,
                 Filters=[{"Name": "image-id", "Values": [rid]}])
    return result(f, errors, exists=True, public=img.get("Public"), name=img.get("Name"),
                  created_days_ago=days_since(img.get("CreationDate")),
                  shared_with_accounts=[p["UserId"] for p in lp if p.get("UserId")][:MAX_ITEMS],
                  shared_with_org=[p.get("OrganizationArn") or p.get("OrganizationalUnitArn") for p in lp
                                   if p.get("OrganizationArn") or p.get("OrganizationalUnitArn")],
                  instances_using=None if users is None else
                  sum(len(r.get("Instances", [])) for r in users.get("Reservations", [])),
                  deprecation_time=img.get("DeprecationTime"))


def _eip(f, ec2, errors):
    rid = f["resource_id"]
    key = {"AllocationIds": [rid]} if rid.startswith("eipalloc-") else {"PublicIps": [rid]}
    resp = call(errors, "DescribeAddresses", ec2.describe_addresses, **key,
                absent=("InvalidAllocationID.NotFound", "InvalidAddress.NotFound"))
    a = next(iter(ok(resp).get("Addresses", [])), None)
    if not a:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    return result(f, errors, exists=True, public_ip=a.get("PublicIp"),
                  associated=bool(a.get("AssociationId")), instance=a.get("InstanceId"),
                  network_interface=a.get("NetworkInterfaceId"), tags=_tags(a))


def _nat(f, ec2, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeNatGateways", ec2.describe_nat_gateways, NatGatewayIds=[rid],
                absent=("NatGatewayNotFound",))
    nat = next(iter(ok(resp).get("NatGateways", [])), None)
    if not nat:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    routes = call(errors, "DescribeRouteTables", ec2.describe_route_tables,
                  Filters=[{"Name": "route.nat-gateway-id", "Values": [rid]}])
    tables = ok(routes).get("RouteTables", [])
    return result(f, errors, exists=True, state=nat.get("State"), vpc=nat.get("VpcId"),
                  connectivity=nat.get("ConnectivityType"), created_days_ago=days_since(nat.get("CreateTime")),
                  route_tables_using=None if routes is None else len(tables),
                  subnets_routed=None if routes is None else sum(len(t.get("Associations", [])) for t in tables),
                  note="Use get_resource_metrics for bytes processed (the real usage signal).")


def _vpc(f, ec2, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeVpcs", ec2.describe_vpcs, VpcIds=[rid], absent=("InvalidVpcID.NotFound",))
    vpc = next(iter(ok(resp).get("Vpcs", [])), None)
    if not vpc:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    enis = call(errors, "DescribeNetworkInterfaces", ec2.describe_network_interfaces,
                Filters=[{"Name": "vpc-id", "Values": [rid]}])
    kinds: dict[str, int] = {}
    for n in ok(enis).get("NetworkInterfaces", []):
        k = n.get("InterfaceType") or "interface"
        if k == "interface":
            k = "ec2" if (n.get("Attachment") or {}).get("InstanceId") else (n.get("RequesterId") or "other")
        kinds[k] = kinds.get(k, 0) + 1
    return result(f, errors, exists=True, is_default=vpc.get("IsDefault"), cidr=vpc.get("CidrBlock"),
                  network_interfaces=None if enis is None else sum(kinds.values()), interfaces_by_kind=kinds,
                  cloudformation_stack=_tags(vpc).get("aws:cloudformation:stack-name"))


def _rds(f, rds, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeDBInstances", rds.describe_db_instances, DBInstanceIdentifier=rid,
                absent=("DBInstanceNotFound",))
    db = next(iter(ok(resp).get("DBInstances", [])), None)
    if not db:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    return result(f, errors, exists=True, status=db.get("DBInstanceStatus"), engine=db.get("Engine"),
                  instance_class=db.get("DBInstanceClass"), multi_az=db.get("MultiAZ"),
                  backup_retention_days=db.get("BackupRetentionPeriod"),
                  latest_restorable=iso(db.get("LatestRestorableTime")),
                  deletion_protection=db.get("DeletionProtection"), storage_encrypted=db.get("StorageEncrypted"),
                  publicly_accessible=db.get("PubliclyAccessible"), cluster=db.get("DBClusterIdentifier"),
                  read_replicas=db.get("ReadReplicaDBInstanceIdentifiers", []),
                  replica_of=db.get("ReadReplicaSourceDBInstanceIdentifier"),
                  created_days_ago=days_since(db.get("InstanceCreateTime")))


def _rds_snapshot(f, rds, errors):
    rid = f["resource_id"]
    resp = call(errors, "DescribeDBSnapshots", rds.describe_db_snapshots, DBSnapshotIdentifier=rid,
                absent=("DBSnapshotNotFound",))
    snap = next(iter(ok(resp).get("DBSnapshots", [])), None)
    if not snap:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    src = call(errors, "DescribeDBInstances", rds.describe_db_instances,
               DBInstanceIdentifier=snap.get("DBInstanceIdentifier"), absent=("DBInstanceNotFound",))
    return result(f, errors, exists=True, age_days=days_since(snap.get("SnapshotCreateTime")),
                  snapshot_type=snap.get("SnapshotType"), encrypted=snap.get("Encrypted"),
                  size_gb=snap.get("AllocatedStorage"), source_instance=snap.get("DBInstanceIdentifier"),
                  source_instance_exists=None if src is None else src is not ABSENT,
                  managed_by_aws_backup=snap.get("SnapshotType") == "awsbackup" or rid.startswith("awsbackup:"))


def _elb(f, s, errors):
    rid, rtype = f["resource_id"], f["resource_type"]
    elb = s.client("elbv2")
    if rtype.endswith("TargetGroup"):
        key = {"TargetGroupArns": [rid]} if rid.startswith("arn:") else {"Names": [rid]}
        resp = call(errors, "DescribeTargetGroups", elb.describe_target_groups, **key, absent=("TargetGroupNotFound",))
        tg = next(iter(ok(resp).get("TargetGroups", [])), None)
        if not tg:
            return result(f, errors, exists=False if resp is ABSENT or resp else None)
        th = call(errors, "DescribeTargetHealth", elb.describe_target_health, TargetGroupArn=tg["TargetGroupArn"])
        states: dict[str, int] = {}
        for t in ok(th).get("TargetHealthDescriptions", []):
            st = t.get("TargetHealth", {}).get("State")
            states[st] = states.get(st, 0) + 1
        return result(f, errors, exists=True, load_balancers=tg.get("LoadBalancerArns", []),
                      target_type=tg.get("TargetType"), target_states=states,
                      health_check_path=tg.get("HealthCheckPath"))
    key = {"LoadBalancerArns": [rid]} if rid.startswith("arn:") else {"Names": [rid]}
    resp = call(errors, "DescribeLoadBalancers", elb.describe_load_balancers, **key, absent=("LoadBalancerNotFound",))
    lb = next(iter(ok(resp).get("LoadBalancers", [])), None)
    if not lb:
        return result(f, errors, exists=False if resp is ABSENT or resp else None)
    return result(f, errors, exists=True, state=lb.get("State", {}).get("Code"), scheme=lb.get("Scheme"),
                  type=lb.get("Type"), created_days_ago=days_since(lb.get("CreatedTime")))


@tool(context=True)
def get_resource_state(tool_context: ToolContext) -> dict:
    """Lifecycle state of the finding's resource and what still depends on it.

    EC2 instance: state, days stopped, volumes, Auto Scaling / CloudFormation ownership,
    termination protection. EBS volume: attachments, age. EBS snapshot: age, AMIs built on it,
    whether its source volume exists, whether AWS Backup or DLM manages it. AMI: public or
    shared, instances launched from it. Elastic IP: association. NAT gateway: route tables
    using it. VPC: default or not, network interfaces by kind. RDS instance: status, Multi-AZ,
    backups, deletion protection, replicas. RDS snapshot: age, type, source instance.
    Load balancer / target group: state and target health.
    exists=False means the resource is gone: the finding is stale.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, errors = finding_session(f), f["resource_type"], []
    ec2_handlers = {"AWS::EC2::Instance": _ec2_instance, "AWS::EC2::Volume": _volume,
                    "AWS::EC2::Snapshot": _snapshot, "AWS::EC2::Image": _image, "AWS::EC2::EIP": _eip,
                    "AWS::EC2::NatGateway": _nat, "AWS::EC2::VPC": _vpc}
    if rtype in ec2_handlers:
        return ec2_handlers[rtype](f, s.client("ec2"), errors)
    if rtype == "AWS::RDS::DBInstance":
        return _rds(f, s.client("rds"), errors)
    if rtype == "AWS::RDS::DBSnapshot":
        return _rds_snapshot(f, s.client("rds"), errors)
    if rtype.startswith("AWS::ElasticLoadBalancingV2::"):
        return _elb(f, s, errors)
    return result(f, errors, note=f"no lifecycle check defined for {rtype}.")


INFRA_TOOLS = [get_resource_state]
