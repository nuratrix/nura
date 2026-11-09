# Deploy the Nura judgment layer to Bedrock AgentCore Runtime as a container.
#
#   .\deploy\deploy_runtime.ps1            # first deploy and every redeploy
#
# Needs the foundation first (deploy_judgement_foundation.ps1): table, bucket and topic names come
# from that stack's outputs, so nothing here is specific to one account.
# 1. IAM role nura-judgment-runtime (deploy/iam/*.json, placeholders filled from the stack)
# 2. agentcore configure: uses ./Dockerfile, writes .bedrock_agentcore.yaml
# 3. agentcore launch: CodeBuild builds the ARM64 image, pushes to ECR, creates/updates the runtime
# Run from the project root. Needs credentials with IAM, ECR, CodeBuild and bedrock-agentcore rights.
param(
    [string]$Region = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { "us-east-1" }),
    [string]$Agent = "nura_judgment",                    # AgentCore name: letters, digits, _
    [string]$ModelId = "amazon.nova-pro-v1:0",
    [string]$MemberRoleName = "governance-platform-reader",
    [string]$MemberRoleExternalId = "governance-platform"
)
$ErrorActionPreference = "Stop"
$env:AGENTCORE_SUPPRESS_RECOMMENDATION = "1"
$env:PYTHONIOENCODING = "utf-8"            # the toolkit prints emoji; cp1252 consoles crash on them
$Role  = "nura-judgment-runtime"
$Stack = "nura-judgment-foundation"

function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

$Account = (aws sts get-caller-identity --query Account --output text); Check "sts get-caller-identity"

# ---- foundation outputs ----
$ErrorActionPreference = "Continue"
$json = aws cloudformation describe-stacks --stack-name $Stack --region $Region --query "Stacks[0].Outputs" --output json 2>$null
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) { throw "Stack $Stack not found in $Region. Run .\deploy\deploy_judgement_foundation.ps1 first." }
$out = @{}
($json | ConvertFrom-Json) | ForEach-Object { $out[$_.OutputKey] = $_.OutputValue }
Write-Host "Account $Account, region $Region"
Write-Host "  table $($out.FindingsTableName), bucket $($out.DecisionLogBucket), topic $($out.FindingsTopicArn)"

# ---- 1. execution role (policy files are templates) ----
$fill = @{
    "__ACCOUNT_ID__" = $Account; "__REGION__" = $Region; "__AGENT__" = $Agent
    "__FINDINGS_TABLE__" = $out.FindingsTableName; "__DECISION_LOG_BUCKET__" = $out.DecisionLogBucket
    "__FINDINGS_TOPIC_ARN__" = $out.FindingsTopicArn; "__MEMBER_ROLE_NAME__" = $MemberRoleName
}
$policies = @{}
foreach ($name in "trust-policy", "runtime-policy") {
    $text = Get-Content "deploy/iam/$name.json" -Raw
    foreach ($k in $fill.Keys) { $text = $text.Replace($k, $fill[$k]) }
    if ($text -match "__[A-Z_]+__") { throw "Unfilled placeholder $($Matches[0]) in deploy/iam/$name.json" }
    $path = Join-Path $env:TEMP "nura-$name.json"
    [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding $false))
    $policies[$name] = "file://$path"
}

$ErrorActionPreference = "Continue"        # PS 5.1 turns native stderr into errors under Stop
aws iam get-role --role-name $Role --query Role.Arn --output text 2>$null | Out-Null
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Creating role $Role"
    aws iam create-role --role-name $Role --assume-role-policy-document $policies["trust-policy"] `
        --description "Nura judgment layer on AgentCore Runtime" | Out-Null
    Check "create-role"
    $NewRole = $true
} else {
    aws iam update-assume-role-policy --role-name $Role --policy-document $policies["trust-policy"]
    Check "update-assume-role-policy"
}
aws iam put-role-policy --role-name $Role --policy-name nura-judgment --policy-document $policies["runtime-policy"]
Check "put-role-policy"
$RoleArn = (aws iam get-role --role-name $Role --query Role.Arn --output text)
if ($NewRole) { Write-Host "Waiting 15s for the new role to propagate"; Start-Sleep -Seconds 15 }

# ---- 2. configure (idempotent; rewrites .bedrock_agentcore.yaml) ----
uv run agentcore configure --entrypoint main.py --name $Agent `
    --execution-role $RoleArn --deployment-type container `
    --region $Region --non-interactive
Check "agentcore configure"

# ---- 3. build + deploy ----
uv run agentcore launch --agent $Agent --auto-update-on-conflict `
    --env AWS_REGION=$Region --env AWS_DEFAULT_REGION=$Region `
    --env FINDINGS_TABLE=$($out.FindingsTableName) `
    --env FINDINGS_TOPIC_ARN=$($out.FindingsTopicArn) `
    --env DECISION_LOG_BUCKET=$($out.DecisionLogBucket) `
    --env DECISION_LOG_RETENTION_DAYS=$($out.DecisionLogRetentionDays) `
    --env DECISION_LOG_LOCK_MODE=$($out.DecisionLogLockMode) `
    --env BEDROCK_MODEL_ID=$ModelId `
    --env MEMBER_ROLE_NAME=$MemberRoleName `
    --env MEMBER_ROLE_EXTERNAL_ID=$MemberRoleExternalId
Check "agentcore launch"

uv run agentcore status --agent $Agent
Write-Host ""
Write-Host "Next: rerun .\deploy\deploy_judgement_foundation.ps1 to connect the invoker Lambda to this runtime."
