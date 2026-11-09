"""Security context tools: exposure, identity power and existing detections for the finding's resource.

Like tags.py and cloudtrail.py, every tool reads the resource, account and region from the
finding under review (invocation_state), never from the model, and is read-only. Tools
return facts, not verdicts: the agent judges. Each AWS call is tried on its own, so one
denied or missing call leaves the rest of the answer intact; failures are listed in
`errors`, and "not configured" (no bucket policy, no Security Hub) is reported as a fact.
Nothing here reads data: no object contents, no secret values, no raw policies returned.
"""
from __future__ import annotations

import json
import re

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT as _ABSENT, MAX_ITEMS, as_list as _as_list, call as _call
from agents.tools.context.aws_calls import days_since as _days_since, name_of as _name, result as _result
from agents.tools.context.finding_context import current_finding, finding_session, resource_arn

OPEN_CIDRS = ("0.0.0.0/0", "::/0")
PUBLIC_ACL_GROUPS = ("http://acs.amazonaws.com/groups/global/AllUsers",
                     "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


# ---------------------------------------------------------------- helpers

def summarize_policy(document, own_account: str) -> dict:
    """Who a resource / trust policy lets in from outside the account. Allow statements only.

    public: Principal "*" (or AWS "*"). has_condition matters: a public grant limited by
    aws:SourceVpce / aws:PrincipalOrgID is very different from an unconditional one.
    """
    doc = json.loads(document) if isinstance(document, str) else (document or {})
    statements = _as_list(doc.get("Statement"))
    notable, external, services = [], set(), set()
    public_unconditional = public_conditional = False
    for s in statements:
        if s.get("Effect") != "Allow":
            continue
        p = s.get("Principal")
        principals = ["*"] if p == "*" else [x for v in (p or {}).values() for x in _as_list(v)]
        services |= {x for x in principals if x.endswith(".amazonaws.com")}
        public = "*" in principals
        accounts = {m.group(1) for x in principals
                    for m in [re.match(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)", str(x))] if m}
        accounts.discard(own_account)
        if not (public or accounts):
            continue
        cond = s.get("Condition") or {}
        if public:
            public_conditional |= bool(cond)
            public_unconditional |= not cond
        external |= accounts
        notable.append({"sid": s.get("Sid"), "public": public, "external_accounts": sorted(accounts),
                        "actions": _as_list(s.get("Action"))[:MAX_ITEMS],
                        "condition_keys": sorted({k for op in cond.values() for k in op})})
    return {"statements": len(statements), "public_unconditional": public_unconditional,
            "public_with_condition": public_conditional, "external_accounts": sorted(external),
            "service_principals": sorted(services), "grants": notable[:MAX_ITEMS]}


def _is_admin(document) -> bool:
    doc = json.loads(document) if isinstance(document, str) else (document or {})
    for s in _as_list(doc.get("Statement")):
        actions, resources = _as_list(s.get("Action")), _as_list(s.get("Resource"))
        if s.get("Effect") == "Allow" and {"*", "*:*"} & set(actions) and "*" in resources:
            return True
    return False


def _open_ingress(ec2, group_ids: list, errors: list) -> list[dict]:
    """Ingress rules open to the internet (0.0.0.0/0 or ::/0) on these security groups."""
    if not group_ids:
        return []
    resp = _call(errors, "DescribeSecurityGroups", ec2.describe_security_groups, GroupIds=list(group_ids))
    rules = []
    for g in (resp or {}).get("SecurityGroups", []) if resp is not _ABSENT else []:
        for perm in g.get("IpPermissions", []):
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + \
                    [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
            for cidr in (c for c in cidrs if c in OPEN_CIDRS):
                proto = perm.get("IpProtocol")
                rules.append({"group_id": g["GroupId"], "protocol": "all" if proto == "-1" else proto,
                              "ports": "all" if proto == "-1" else f"{perm.get('FromPort')}-{perm.get('ToPort')}",
                              "source": cidr})
    return rules


# ---------------------------------------------------------------- 1. resource policy

@tool(context=True)
def get_resource_policy(tool_context: ToolContext) -> dict:
    """Who can reach the finding's resource through its own access controls.

    S3 bucket: public access block (bucket and account), policy status, bucket policy and ACL
    grants. KMS key: key policy and rotation. Lambda: function policy and function URL auth.
    ECR repository, Secrets Manager secret: resource policy. RDS snapshot: who may restore it.
    Policies are summarised (public / cross-account grants and their conditions), not returned raw.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, acct, errors = finding_session(f), f["resource_type"], f["resource_id"], f["account_id"], []

    if rtype == "AWS::S3::Bucket":
        s3, bucket = s.client("s3"), _name(rid).split(":::")[-1]
        pab = _call(errors, "GetPublicAccessBlock", s3.get_public_access_block, Bucket=bucket,
                    absent=("NoSuchPublicAccessBlockConfiguration",))
        acct_pab = _call(errors, "GetAccountPublicAccessBlock",
                         s.client("s3control").get_public_access_block, AccountId=acct,
                         absent=("NoSuchPublicAccessBlockConfiguration",))
        status = _call(errors, "GetBucketPolicyStatus", s3.get_bucket_policy_status, Bucket=bucket,
                       absent=("NoSuchBucketPolicy",))
        policy = _call(errors, "GetBucketPolicy", s3.get_bucket_policy, Bucket=bucket,
                       absent=("NoSuchBucketPolicy",))
        acl = _call(errors, "GetBucketAcl", s3.get_bucket_acl, Bucket=bucket)
        conf = lambda r: None if r is None else ({} if r is _ABSENT else r["PublicAccessBlockConfiguration"])
        return _result(
            f, errors,
            bucket_public_access_block=conf(pab), account_public_access_block=conf(acct_pab),
            policy_is_public=None if status in (None, _ABSENT) else status["PolicyStatus"]["IsPublic"],
            policy=None if policy is None else ("none" if policy is _ABSENT
                                                else summarize_policy(policy["Policy"], acct)),
            public_acl_grants=None if acl is None else [
                {"grantee": g["Grantee"].get("URI"), "permission": g.get("Permission")}
                for g in acl.get("Grants", []) if g.get("Grantee", {}).get("URI") in PUBLIC_ACL_GROUPS])

    if rtype == "AWS::KMS::Key":
        kms = s.client("kms")
        policy = _call(errors, "GetKeyPolicy", kms.get_key_policy, KeyId=rid, PolicyName="default")
        rot = _call(errors, "GetKeyRotationStatus", kms.get_key_rotation_status, KeyId=rid)
        return _result(f, errors, policy=None if policy is None else summarize_policy(policy["Policy"], acct),
                       rotation_enabled=None if rot is None else rot.get("KeyRotationEnabled"))

    if rtype == "AWS::Lambda::Function":
        lam = s.client("lambda")
        policy = _call(errors, "GetPolicy", lam.get_policy, FunctionName=rid, absent=("ResourceNotFoundException",))
        urls = _call(errors, "ListFunctionUrlConfigs", lam.list_function_url_configs, FunctionName=rid)
        return _result(
            f, errors,
            policy=None if policy is None else ("none" if policy is _ABSENT
                                                else summarize_policy(policy["Policy"], acct)),
            function_urls=None if urls is None else [{"auth_type": u.get("AuthType"), "url": u.get("FunctionUrl")}
                                                     for u in urls.get("FunctionUrlConfigs", [])])

    simple = {
        "AWS::ECR::Repository": ("ecr", "GetRepositoryPolicy", "get_repository_policy",
                                 {"repositoryName": _name(rid)}, "policyText", ("RepositoryPolicyNotFoundException",)),
        "AWS::SecretsManager::Secret": ("secretsmanager", "GetResourcePolicy", "get_resource_policy",
                                        {"SecretId": rid}, "ResourcePolicy", ()),
    }
    if rtype in simple:
        svc, label, method, kwargs, field, absent = simple[rtype]
        resp = _call(errors, label, getattr(s.client(svc), method), absent=absent, **kwargs)
        doc = None if resp in (None, _ABSENT) else resp.get(field)
        return _result(f, errors, policy=None if resp is None else
                       (summarize_policy(doc, acct) if doc else "none"))

    if rtype == "AWS::RDS::DBSnapshot":
        resp = _call(errors, "DescribeDBSnapshotAttributes",
                     s.client("rds").describe_db_snapshot_attributes, DBSnapshotIdentifier=rid)
        restore = []
        for a in (resp or {}).get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
            if a.get("AttributeName") == "restore":
                restore = a.get("AttributeValues", [])
        return _result(f, errors, restorable_by=None if resp is None else restore,
                       public=None if resp is None else "all" in restore)

    return _result(f, errors, note=f"{rtype} has no resource policy this tool reads; "
                                   "use get_network_exposure or get_principal_access.")


# ---------------------------------------------------------------- 2. network exposure

@tool(context=True)
def get_network_exposure(tool_context: ToolContext) -> dict:
    """Whether the finding's resource is reachable from the internet, and whether it is in use.

    Security group: rules open to 0.0.0.0/0 or ::/0 and the network interfaces using it.
    EC2 instance: state, public IP, IMDSv2, open rules on its security groups.
    RDS instance / cluster: publicly accessible, encryption, open rules. EKS cluster: public
    endpoint and allowed CIDRs. Lambda: VPC attachment and function URL auth.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, errors = finding_session(f), f["resource_type"], f["resource_id"], []

    if rtype == "AWS::EC2::SecurityGroup":
        ec2 = s.client("ec2")
        enis = _call(errors, "DescribeNetworkInterfaces", ec2.describe_network_interfaces,
                     Filters=[{"Name": "group-id", "Values": [rid]}])
        users = [{"eni": n.get("NetworkInterfaceId"), "attached_to": (n.get("Attachment") or {}).get("InstanceId")
                  or n.get("Description"), "public_ip": (n.get("Association") or {}).get("PublicIp")}
                 for n in (enis or {}).get("NetworkInterfaces", [])]
        return _result(f, errors, open_ingress=_open_ingress(ec2, [rid], errors),
                       in_use=None if enis is None else bool(users),
                       network_interfaces=len(users) if enis is not None else None, used_by=users[:MAX_ITEMS])

    if rtype == "AWS::EC2::Instance":
        ec2 = s.client("ec2")
        resp = _call(errors, "DescribeInstances", ec2.describe_instances, InstanceIds=[rid])
        inst = next((i for r in (resp or {}).get("Reservations", []) for i in r.get("Instances", [])), None)
        if inst is None:
            return _result(f, errors, note="instance not found" if resp else None)
        groups = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
        return _result(f, errors, state=inst.get("State", {}).get("Name"),
                       public_ip=inst.get("PublicIpAddress"),
                       imds_tokens=inst.get("MetadataOptions", {}).get("HttpTokens"),
                       instance_profile=(inst.get("IamInstanceProfile") or {}).get("Arn"),
                       security_groups=groups, open_ingress=_open_ingress(ec2, groups, errors))

    if rtype in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
        rds, ec2 = s.client("rds"), s.client("ec2")
        if rtype == "AWS::RDS::DBInstance":
            resp = _call(errors, "DescribeDBInstances", rds.describe_db_instances, DBInstanceIdentifier=rid)
            dbs = (resp or {}).get("DBInstances", [])
        else:
            resp = _call(errors, "DescribeDBClusters", rds.describe_db_clusters, DBClusterIdentifier=rid)
            dbs = (resp or {}).get("DBClusters", [])
        if not dbs:
            return _result(f, errors, note="database not found" if resp else None)
        db = dbs[0]
        groups = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])]
        facts = {"status": db.get("DBInstanceStatus") or db.get("Status"),
                 "storage_encrypted": db.get("StorageEncrypted"),
                 "deletion_protection": db.get("DeletionProtection"),
                 "security_groups": groups, "open_ingress": _open_ingress(ec2, groups, errors)}
        if rtype == "AWS::RDS::DBInstance":
            facts["publicly_accessible"] = db.get("PubliclyAccessible")
        else:
            members = _call(errors, "DescribeDBInstances", rds.describe_db_instances,
                            Filters=[{"Name": "db-cluster-id", "Values": [rid]}])
            facts["public_members"] = None if members is None else [
                m["DBInstanceIdentifier"] for m in members.get("DBInstances", []) if m.get("PubliclyAccessible")]
        return _result(f, errors, **facts)

    if rtype == "AWS::EKS::Cluster":
        resp = _call(errors, "DescribeCluster", s.client("eks").describe_cluster, name=_name(rid))
        vpc = (resp or {}).get("cluster", {}).get("resourcesVpcConfig", {})
        if resp is None:
            return _result(f, errors)
        sg = vpc.get("clusterSecurityGroupId")
        return _result(f, errors, endpoint_public_access=vpc.get("endpointPublicAccess"),
                       endpoint_private_access=vpc.get("endpointPrivateAccess"),
                       public_access_cidrs=vpc.get("publicAccessCidrs"),
                       open_ingress=_open_ingress(s.client("ec2"), [sg] if sg else [], errors))

    if rtype == "AWS::Lambda::Function":
        lam = s.client("lambda")
        conf = _call(errors, "GetFunctionConfiguration", lam.get_function_configuration, FunctionName=rid)
        urls = _call(errors, "ListFunctionUrlConfigs", lam.list_function_url_configs, FunctionName=rid)
        return _result(f, errors, in_vpc=None if conf is None else bool((conf.get("VpcConfig") or {}).get("VpcId")),
                       function_url_auth=None if urls is None else
                       [u.get("AuthType") for u in urls.get("FunctionUrlConfigs", [])])

    return _result(f, errors, note=f"{rtype} has no network exposure this tool reads.")


# ---------------------------------------------------------------- 3. principal access

@tool(context=True)
def get_principal_access(tool_context: ToolContext) -> dict:
    """How powerful an IAM identity is and whether it is actually used.

    IAM user: admin policies (direct, group, inline), MFA, console password last use, access
    keys with age and last use. IAM role: admin policies, last used, who may assume it
    (trust policy summary). Access key: owner, status, age, last use. Root account and
    password policy: account summary (root MFA, root access keys) and the password policy.
    Takes no arguments: the identity comes from the finding under review.
    """
    f = current_finding(tool_context)
    rtype, rid, acct, errors = f["resource_type"], f["resource_id"], f["account_id"], []
    iam = finding_session(f).client("iam")

    def keys_of(user):
        resp = _call(errors, "ListAccessKeys", iam.list_access_keys, UserName=user)
        out = []
        for k in (resp or {}).get("AccessKeyMetadata", []):
            used = _call(errors, "GetAccessKeyLastUsed", iam.get_access_key_last_used, AccessKeyId=k["AccessKeyId"])
            last = (used or {}).get("AccessKeyLastUsed", {})
            out.append({"key_id": k["AccessKeyId"], "status": k.get("Status"),
                        "age_days": _days_since(k.get("CreateDate")),
                        "last_used_days": _days_since(last.get("LastUsedDate")),
                        "last_service": last.get("ServiceName")})
        return None if resp is None else out

    def admin_from(attached, inline_names, get_inline, **who):
        names = [p["PolicyName"] for p in attached]
        admin = "AdministratorAccess" in names
        for name in inline_names[:5]:
            doc = _call(errors, "GetInlinePolicy", get_inline, PolicyName=name, **who)
            admin |= bool(doc) and doc is not _ABSENT and _is_admin(doc["PolicyDocument"])
        return names, admin

    if rtype == "AWS::IAM::User":
        user = _name(rid)
        u = _call(errors, "GetUser", iam.get_user, UserName=user, absent=("NoSuchEntity",))
        if u is _ABSENT:
            return _result(f, errors, note=f"user {user} not found (deleted?)")
        attached = (_call(errors, "ListAttachedUserPolicies", iam.list_attached_user_policies, UserName=user)
                    or {}).get("AttachedPolicies", [])
        inline = (_call(errors, "ListUserPolicies", iam.list_user_policies, UserName=user) or {}).get("PolicyNames", [])
        groups = [g["GroupName"] for g in (_call(errors, "ListGroupsForUser", iam.list_groups_for_user,
                                                 UserName=user) or {}).get("Groups", [])]
        for g in groups[:5]:
            attached += (_call(errors, "ListAttachedGroupPolicies", iam.list_attached_group_policies,
                               GroupName=g) or {}).get("AttachedPolicies", [])
        names, admin = admin_from(attached, inline, iam.get_user_policy, UserName=user)
        login = _call(errors, "GetLoginProfile", iam.get_login_profile, UserName=user, absent=("NoSuchEntity",))
        mfa = _call(errors, "ListMFADevices", iam.list_mfa_devices, UserName=user)
        return _result(f, errors, is_admin=admin, policies=names, inline_policies=inline, groups=groups,
                       console_access=None if login is None else login is not _ABSENT,
                       password_last_used_days=_days_since((u or {}).get("User", {}).get("PasswordLastUsed")),
                       mfa_devices=None if mfa is None else len(mfa.get("MFADevices", [])),
                       access_keys=keys_of(user))

    if rtype == "AWS::IAM::Role":
        role = _name(rid)
        r = _call(errors, "GetRole", iam.get_role, RoleName=role, absent=("NoSuchEntity",))
        if r is _ABSENT:
            return _result(f, errors, note=f"role {role} not found (deleted?)")
        attached = (_call(errors, "ListAttachedRolePolicies", iam.list_attached_role_policies, RoleName=role)
                    or {}).get("AttachedPolicies", [])
        inline = (_call(errors, "ListRolePolicies", iam.list_role_policies, RoleName=role) or {}).get("PolicyNames", [])
        names, admin = admin_from(attached, inline, iam.get_role_policy, RoleName=role)
        role_doc = (r or {}).get("Role", {})
        return _result(f, errors, is_admin=admin, policies=names, inline_policies=inline,
                       last_used_days=_days_since(role_doc.get("RoleLastUsed", {}).get("LastUsedDate")),
                       trust=summarize_policy(role_doc["AssumeRolePolicyDocument"], acct) if role_doc else None)

    if rtype == "AWS::IAM::AccessKey":
        used = _call(errors, "GetAccessKeyLastUsed", iam.get_access_key_last_used, AccessKeyId=rid)
        user = (used or {}).get("UserName")
        key = next((k for k in (keys_of(user) or []) if k["key_id"] == rid), None) if user else None
        return _result(f, errors, user=user, key=key)

    if rtype in ("AWS::IAM::RootAccount", "AWS::IAM::PasswordPolicy"):
        summary = (_call(errors, "GetAccountSummary", iam.get_account_summary) or {}).get("SummaryMap", {})
        pp = _call(errors, "GetAccountPasswordPolicy", iam.get_account_password_policy, absent=("NoSuchEntity",))
        return _result(f, errors, root_mfa_enabled=summary.get("AccountMFAEnabled") == 1 if summary else None,
                       root_access_keys_present=summary.get("AccountAccessKeysPresent") == 1 if summary else None,
                       password_policy=None if pp is None else ("none" if pp is _ABSENT else pp["PasswordPolicy"]))

    return _result(f, errors, note=f"{rtype} is not an IAM identity; use get_resource_policy.")


# ---------------------------------------------------------------- 4. existing detections

GUARDDUTY_FIELDS = {
    "AWS::EC2::Instance": "resource.instanceDetails.instanceId",
    "AWS::S3::Bucket": "resource.s3BucketDetails.name",
    "AWS::IAM::User": "resource.accessKeyDetails.userName",
    "AWS::IAM::AccessKey": "resource.accessKeyDetails.accessKeyId",
    "AWS::EKS::Cluster": "resource.eksClusterDetails.name",
    "AWS::RDS::DBInstance": "resource.rdsDbInstanceDetails.dbInstanceIdentifier",
    "AWS::Lambda::Function": "resource.lambdaDetails.functionName",
}


@tool(context=True)
def get_security_signals(tool_context: ToolContext) -> dict:
    """What AWS security services have already detected on the finding's resource.

    Active GuardDuty findings (threats: compromise, exfiltration, crypto-mining), active
    Security Hub findings (aggregated controls and integrations), and active IAM Access
    Analyzer findings (external access). A service that isn't enabled is reported as such.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, acct, errors = finding_session(f), f["resource_type"], f["resource_id"], f["account_id"], []
    arn = resource_arn(f)
    out: dict = {}

    # GuardDuty
    field = GUARDDUTY_FIELDS.get(rtype)
    gd = s.client("guardduty")
    detectors = _call(errors, "ListDetectors", gd.list_detectors)
    det = ((detectors or {}).get("DetectorIds") or [None])[0]
    if detectors is not None and det is None:
        out["guardduty"] = "not enabled"
    elif det and rtype == "AWS::GuardDuty::Finding":
        got = _call(errors, "GetFindings", gd.get_findings, DetectorId=det, FindingIds=[rid])
        out["guardduty"] = [_gd(x) for x in (got or {}).get("Findings", [])]
    elif det and field:
        ids = _call(errors, "ListFindings", gd.list_findings, DetectorId=det, MaxResults=MAX_ITEMS,
                    FindingCriteria={"Criterion": {field: {"Eq": [_name(rid)]},
                                                   "service.archived": {"Eq": ["false"]}}})
        found = (ids or {}).get("FindingIds", [])
        got = _call(errors, "GetFindings", gd.get_findings, DetectorId=det, FindingIds=found) if found else {}
        out["guardduty"] = [_gd(x) for x in (got or {}).get("Findings", [])]
    elif det:
        out["guardduty"] = f"no resource filter for {rtype}"

    # Security Hub (ASFF ResourceId is the ARN; account-level findings use AWS::::Account:<id>)
    sh = _call(errors, "GetFindings(SecurityHub)", s.client("securityhub").get_findings, MaxResults=MAX_ITEMS,
               Filters={"ResourceId": [{"Value": arn or f"AWS::::Account:{acct}", "Comparison": "EQUALS"}],
                        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                        "WorkflowStatus": [{"Value": v, "Comparison": "EQUALS"} for v in ("NEW", "NOTIFIED")]},
               absent=("InvalidAccessException",))
    out["security_hub"] = "not enabled" if sh is _ABSENT else (None if sh is None else [
        {"title": x.get("Title"), "severity": (x.get("Severity") or {}).get("Label"),
         "product": x.get("ProductName"), "compliance": (x.get("Compliance") or {}).get("Status"),
         "updated_days": _days_since(x.get("UpdatedAt"))} for x in sh.get("Findings", [])])

    # IAM Access Analyzer (external access findings on this ARN)
    if arn:
        aa = s.client("accessanalyzer")
        analyzers = _call(errors, "ListAnalyzers", aa.list_analyzers)
        active = [a["arn"] for a in (analyzers or {}).get("analyzers", []) if a.get("status") == "ACTIVE"]
        if analyzers is not None and not active:
            out["access_analyzer"] = "not enabled"
        elif active:
            found = _call(errors, "ListFindingsV2", aa.list_findings_v2, analyzerArn=active[0],
                          maxResults=MAX_ITEMS, filter={"resource": {"eq": [arn]}, "status": {"eq": ["ACTIVE"]}})
            out["access_analyzer"] = [{"type": x.get("findingType"), "status": x.get("status"),
                                       "updated_days": _days_since(x.get("updatedAt"))}
                                      for x in (found or {}).get("findings", [])]
    return _result(f, errors, **out)


def _gd(x: dict) -> dict:
    return {"type": x.get("Type"), "severity": x.get("Severity"), "title": x.get("Title"),
            "count": (x.get("Service") or {}).get("Count"), "updated_days": _days_since(x.get("UpdatedAt"))}


SECURITY_TOOLS = [get_resource_policy, get_network_exposure, get_principal_access, get_security_signals]
