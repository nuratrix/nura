"""Network context: VPC-level controls around the finding's resource.

Security groups, instances and databases are covered by security.get_network_exposure. This
module covers the VPC fabric: flow logs, DNS query logging and DNS Firewall, whether a subnet
is really public, NACL entries open to the internet, peering partners and transit gateway
sharing. Read-only; the resource comes from the finding under review.
"""
from __future__ import annotations

from strands import ToolContext, tool

from agents.tools.context.aws_calls import ABSENT, MAX_ITEMS, call, ok, result
from agents.tools.context.finding_context import current_finding, finding_session
from common.aws_session import base_session

OPEN_CIDRS = ("0.0.0.0/0", "::/0")
PROTOCOLS = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp"}


def _gone(f, errors, resp):
    return result(f, errors, exists=False if resp is ABSENT or resp else None)


def _vpc_controls(s, vpc_id: str, errors: list) -> dict:
    """Flow logs, DNS query logging and DNS Firewall on one VPC."""
    ec2 = s.client("ec2")
    r53 = s.client("route53resolver")
    fl = call(errors, "DescribeFlowLogs", ec2.describe_flow_logs,
              Filter=[{"Name": "resource-id", "Values": [vpc_id]}])
    qlog = call(errors, "ListResolverQueryLogConfigAssociations", r53.list_resolver_query_log_config_associations,
                Filters=[{"Name": "ResourceId", "Values": [vpc_id]}])
    fw = call(errors, "ListFirewallRuleGroupAssociations", r53.list_firewall_rule_group_associations, VpcId=vpc_id)
    return {
        "flow_logs": None if fl is None else [
            {"status": x.get("FlowLogStatus"), "traffic": x.get("TrafficType"),
             "destination": x.get("LogDestinationType"), "delivery_error": x.get("DeliverLogsErrorMessage")}
            for x in fl.get("FlowLogs", [])],
        "dns_query_logging": None if qlog is None else [
            x.get("Status") for x in qlog.get("ResolverQueryLogConfigAssociations", [])],
        "dns_firewall_rule_groups": None if fw is None else [
            {"name": x.get("Name"), "status": x.get("Status"), "priority": x.get("Priority")}
            for x in fw.get("FirewallRuleGroupAssociations", [])],
    }


def _open_nacl_entries(acl: dict) -> list[dict]:
    """Inbound entries from the internet, in evaluation order (lowest rule number first)."""
    out = []
    for e in sorted(acl.get("Entries", []), key=lambda e: e.get("RuleNumber", 0)):
        if e.get("Egress") or (e.get("CidrBlock") or e.get("Ipv6CidrBlock")) not in OPEN_CIDRS:
            continue
        if e.get("RuleNumber") == 32767:   # the implicit final deny
            continue
        pr = e.get("PortRange") or {}
        out.append({"rule": e.get("RuleNumber"), "action": e.get("RuleAction"),
                    "protocol": PROTOCOLS.get(e.get("Protocol"), e.get("Protocol")),
                    "ports": "all" if not pr else f"{pr.get('From')}-{pr.get('To')}"})
    return out


@tool(context=True)
def get_network_config(tool_context: ToolContext) -> dict:
    """VPC-level network controls for the finding's resource.

    VPC: default or not, internet gateway, flow logs (status, delivery errors), DNS query
    logging and DNS Firewall associations, network interfaces in it. Subnet: auto-assign public
    IP, whether its route table really routes to an internet gateway, interfaces with public
    IPs. Internet gateway: attachments. Network ACL: default or not, subnets it guards, inbound
    entries open to the internet in evaluation order. VPC peering: both sides' accounts and
    whether the other account belongs to your AWS Organization. Transit gateway: auto-accept
    and default route table settings, attachments by owner account. Resolver findings use the
    VPC id. For security groups use get_network_exposure.
    Takes no arguments: the resource comes from the finding under review.
    """
    f = current_finding(tool_context)
    s, rtype, rid, errors = finding_session(f), f["resource_type"], f["resource_id"], []
    ec2 = s.client("ec2")

    if rtype == "AWS::EC2::VPC" or rtype.startswith("AWS::Route53Resolver::"):
        vpc_id = rid if rid.startswith("vpc-") else (f.get("evidence") or {}).get("vpc_id")
        if not vpc_id:
            return result(f, errors, note="finding does not name a VPC id")
        resp = call(errors, "DescribeVpcs", ec2.describe_vpcs, VpcIds=[vpc_id], absent=("InvalidVpcID.NotFound",))
        vpc = next(iter(ok(resp).get("Vpcs", [])), None)
        if not vpc:
            return _gone(f, errors, resp)
        igw = call(errors, "DescribeInternetGateways", ec2.describe_internet_gateways,
                   Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
        enis = call(errors, "DescribeNetworkInterfaces", ec2.describe_network_interfaces,
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        nis = ok(enis).get("NetworkInterfaces", [])
        return result(f, errors, exists=True, vpc_id=vpc_id, is_default=vpc.get("IsDefault"),
                      internet_gateway=None if igw is None else bool(igw.get("InternetGateways")),
                      network_interfaces=None if enis is None else len(nis),
                      public_interfaces=None if enis is None else sum(1 for n in nis if n.get("Association")),
                      **_vpc_controls(s, vpc_id, errors))

    if rtype == "AWS::EC2::Subnet":
        resp = call(errors, "DescribeSubnets", ec2.describe_subnets, SubnetIds=[rid],
                    absent=("InvalidSubnetID.NotFound",))
        sub = next(iter(ok(resp).get("Subnets", [])), None)
        if not sub:
            return _gone(f, errors, resp)
        rts = call(errors, "DescribeRouteTables", ec2.describe_route_tables,
                   Filters=[{"Name": "association.subnet-id", "Values": [rid]}])
        tables = ok(rts).get("RouteTables", [])
        if rts is not None and not tables:   # no explicit association: the VPC's main route table applies
            rts = call(errors, "DescribeRouteTables main", ec2.describe_route_tables,
                       Filters=[{"Name": "vpc-id", "Values": [sub["VpcId"]]},
                                {"Name": "association.main", "Values": ["true"]}])
            tables = ok(rts).get("RouteTables", [])
        igw_route = any(r.get("GatewayId", "").startswith("igw-") and r.get("DestinationCidrBlock") in OPEN_CIDRS
                        for t in tables for r in t.get("Routes", []))
        enis = call(errors, "DescribeNetworkInterfaces", ec2.describe_network_interfaces,
                    Filters=[{"Name": "subnet-id", "Values": [rid]}])
        nis = ok(enis).get("NetworkInterfaces", [])
        return result(f, errors, exists=True, vpc_id=sub.get("VpcId"),
                      map_public_ip_on_launch=sub.get("MapPublicIpOnLaunch"),
                      routes_to_internet_gateway=None if rts is None else igw_route,
                      name=next((t["Value"] for t in sub.get("Tags", []) if t["Key"] == "Name"), None),
                      network_interfaces=None if enis is None else len(nis),
                      interfaces_with_public_ip=None if enis is None else sum(1 for n in nis if n.get("Association")))

    if rtype == "AWS::EC2::InternetGateway":
        resp = call(errors, "DescribeInternetGateways", ec2.describe_internet_gateways, InternetGatewayIds=[rid],
                    absent=("InvalidInternetGatewayID.NotFound",))
        igw = next(iter(ok(resp).get("InternetGateways", [])), None)
        if not igw:
            return _gone(f, errors, resp)
        return result(f, errors, exists=True,
                      attachments=[{"vpc": a.get("VpcId"), "state": a.get("State")} for a in igw.get("Attachments", [])],
                      tags={t["Key"]: t["Value"] for t in igw.get("Tags", [])})

    if rtype == "AWS::EC2::NetworkAcl":
        resp = call(errors, "DescribeNetworkAcls", ec2.describe_network_acls, NetworkAclIds=[rid],
                    absent=("InvalidNetworkAclID.NotFound",))
        acl = next(iter(ok(resp).get("NetworkAcls", [])), None)
        if not acl:
            return _gone(f, errors, resp)
        return result(f, errors, exists=True, is_default=acl.get("IsDefault"), vpc_id=acl.get("VpcId"),
                      subnets=[a.get("SubnetId") for a in acl.get("Associations", [])][:MAX_ITEMS],
                      open_inbound_entries=_open_nacl_entries(acl),
                      note="NACLs are stateless and evaluated lowest rule number first; a lower DENY wins.")

    if rtype == "AWS::EC2::VPCPeeringConnection":
        resp = call(errors, "DescribeVpcPeeringConnections", ec2.describe_vpc_peering_connections,
                    VpcPeeringConnectionIds=[rid], absent=("InvalidVpcPeeringConnectionID.NotFound",))
        pcx = next(iter(ok(resp).get("VpcPeeringConnections", [])), None)
        if not pcx:
            return _gone(f, errors, resp)
        req, acc = pcx.get("RequesterVpcInfo", {}), pcx.get("AccepterVpcInfo", {})
        other = acc.get("OwnerId") if req.get("OwnerId") == f["account_id"] else req.get("OwnerId")
        return result(f, errors, exists=True, status=pcx.get("Status", {}).get("Code"),
                      requester={"account": req.get("OwnerId"), "vpc": req.get("VpcId"), "region": req.get("Region")},
                      accepter={"account": acc.get("OwnerId"), "vpc": acc.get("VpcId"), "region": acc.get("Region")},
                      other_account=other, other_account_in_org=_in_org(other, errors))

    if rtype == "AWS::EC2::TransitGateway":
        resp = call(errors, "DescribeTransitGateways", ec2.describe_transit_gateways, TransitGatewayIds=[rid],
                    absent=("InvalidTransitGatewayID.NotFound",))
        tgw = next(iter(ok(resp).get("TransitGateways", [])), None)
        if not tgw:
            return _gone(f, errors, resp)
        opts = tgw.get("Options", {})
        att = call(errors, "DescribeTransitGatewayAttachments", ec2.describe_transit_gateway_attachments,
                   Filters=[{"Name": "transit-gateway-id", "Values": [rid]}])
        by_owner: dict[str, int] = {}
        for a in ok(att).get("TransitGatewayAttachments", []):
            by_owner[a.get("ResourceOwnerId")] = by_owner.get(a.get("ResourceOwnerId"), 0) + 1
        return result(f, errors, exists=True, state=tgw.get("State"),
                      auto_accept_shared_attachments=opts.get("AutoAcceptSharedAttachments"),
                      default_route_table_association=opts.get("DefaultRouteTableAssociation"),
                      default_route_table_propagation=opts.get("DefaultRouteTablePropagation"),
                      attachments_by_account=by_owner,
                      external_accounts={a: _in_org(a, errors) for a in by_owner if a != f["account_id"]})

    return result(f, errors, note=f"{rtype} is not a VPC-level resource; use get_network_exposure.")


def _in_org(account_id: str | None, errors: list) -> bool | None:
    """Whether account_id is in this AWS Organization. Needs the governance account to be the
    management or a delegated-admin account; None when that can't be determined."""
    if not account_id:
        return None
    org = base_session().client("organizations")
    resp = call(errors, "Organizations DescribeAccount", org.describe_account, AccountId=account_id,
                absent=("AccountNotFoundException",))
    return None if resp is None else resp is not ABSENT


NETWORK_TOOLS = [get_network_config]
