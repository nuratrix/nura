# Deploy the Nura judgment layer foundation (stack nura-judgment-foundation):
#   Findings table, decision log bucket (S3 Object Lock), SNS topic, nura-high-critical queue (+ DLQ),
#   triage Lambda (Findings stream) and, once the AgentCore runtime exists, the invoker Lambda.
#
#   .\deploy\deploy_judgement_foundation.ps1                                   # new account: create everything
#   .\deploy\deploy_judgement_foundation.ps1 -NotificationEmail you@example.com
#   .\deploy\deploy_judgement_foundation.ps1 -DecisionLogBucket decisionlog -TopicName Findings   # reuse existing
#
# Full order:  1. this script   2. deploy_runtime.ps1   3. this script again (adds the invoker)
#
# A table / bucket / topic that already exists under the given name is reused, not recreated
# (and never modified). Resources this stack created stay managed by it on later runs.
param(
    [string]$Region = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { "us-east-1" }),
    [string]$FindingsTable = "Findings",
    [string]$DecisionLogBucket = "",          # default: nura-decisionlog-<account>-<region> (globally unique)
    [string]$TopicName = "nura-findings",
    [string]$NotificationEmail = "",
    # Object Lock retention for decision records. 1 day keeps test records deletable; for production
    # use 2555 (~7 years). deploy_runtime.ps1 reads this from the stack, so both writers agree.
    [int]$RetentionDays = 1,
    [ValidateSet("GOVERNANCE", "COMPLIANCE")][string]$LockMode = "GOVERNANCE",
    [string]$Agent = "nura_judgment"
)
$ErrorActionPreference = "Stop"
$Stack = "nura-judgment-foundation"

# Run an AWS CLI call that may fail without stopping the script (PS 5.1 turns native stderr into
# errors under Stop). Returns stdout ($true if it printed nothing), or $null when the command failed.
function TryAws([scriptblock]$cmd) {
    $ErrorActionPreference = "Continue"
    $out = & $cmd 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    if ($out) { return $out } else { return $true }
}
# Is <logicalId> a resource this stack already manages?
function Owned([string]$logicalId) {
    $id = TryAws { aws cloudformation describe-stack-resource --stack-name $Stack --logical-resource-id $logicalId `
        --region $Region --query StackResourceDetail.PhysicalResourceId --output text }
    return [bool]$id
}

$Account = (aws sts get-caller-identity --query Account --output text)
if ($LASTEXITCODE -ne 0) { throw "No AWS credentials (aws sts get-caller-identity failed)" }
if (-not $DecisionLogBucket) { $DecisionLogBucket = "nura-decisionlog-$Account-$Region" }
Write-Host "Account $Account, region $Region, stack $Stack"

# ---- Findings table: create, or reuse an existing one (it must have a stream) ----
$CreateTable = "true"; $StreamArn = ""
if (-not (Owned "FindingsTable")) {
    $existing = TryAws { aws dynamodb describe-table --table-name $FindingsTable --region $Region `
        --query "Table.[LatestStreamArn, StreamSpecification.StreamViewType]" --output text }
    if ($existing) {
        $CreateTable = "false"
        $StreamArn, $view = ($existing -split "\s+")
        if (-not $StreamArn -or $StreamArn -eq "None" -or $view -ne "NEW_AND_OLD_IMAGES") {
            throw ("Table $FindingsTable exists without a NEW_AND_OLD_IMAGES stream. Enable it, then rerun:`n" +
                "  aws dynamodb update-table --table-name $FindingsTable --stream-specification " +
                "StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES")
        }
        Write-Host "Reusing table   $FindingsTable"
    }
}

# ---- decision log bucket: create, or reuse one you own (it must have Object Lock) ----
$CreateBucket = "true"
if (-not (Owned "DecisionLog")) {
    if (TryAws { aws s3api head-bucket --bucket $DecisionLogBucket --expected-bucket-owner $Account }) {
        $lock = TryAws { aws s3api get-object-lock-configuration --bucket $DecisionLogBucket `
            --query ObjectLockConfiguration.ObjectLockEnabled --output text }
        if ($lock -ne "Enabled") { throw "Bucket $DecisionLogBucket exists without Object Lock; choose another -DecisionLogBucket" }
        $CreateBucket = "false"
        Write-Host "Reusing bucket  $DecisionLogBucket"
    }
}

# ---- SNS topic: create, or reuse ----
$CreateTopic = "true"
if (-not (Owned "FindingsTopic")) {
    $arn = "arn:aws:sns:${Region}:${Account}:$TopicName"
    if (TryAws { aws sns get-topic-attributes --topic-arn $arn --region $Region }) {
        $CreateTopic = "false"
        Write-Host "Reusing topic   $TopicName"
    }
}

# ---- AgentCore runtime (empty -> no invoker yet) ----
$RuntimeArn = (aws bedrock-agentcore-control list-agent-runtimes --region $Region `
    --query "agentRuntimes[?agentRuntimeName=='$Agent'].agentRuntimeArn | [0]" --output text)
if ($LASTEXITCODE -ne 0) { throw "list-agent-runtimes failed" }
if ($RuntimeArn -eq "None") { $RuntimeArn = "" }

# ---- inline the Lambda sources (CloudFormation ZipFile, max 4096 chars each) ----
$template = Get-Content deploy/judgment-foundation.yaml -Raw
foreach ($pair in @(@("INVOKER_CODE", "src/pipeline/invoker.py"),
                    @("TRIAGE_CODE", "src/pipeline/stream_triage.py"))) {
    $code = Get-Content $pair[1] -Raw
    if ($code.Length -ge 4096) { throw "$($pair[1]) is $($code.Length) chars; ZipFile max is 4096" }
    $indented = ($code -split "`r?`n" | ForEach-Object { if ($_) { "          $_" } else { "" } }) -join "`n"
    $template = $template -replace "(?m)^          # $($pair[0]).*$", $indented.Replace('$', '$$')
}
$built = Join-Path $env:TEMP "nura-judgment-foundation.yaml"
[IO.File]::WriteAllText($built, $template, (New-Object Text.UTF8Encoding $false))

# ---- deploy ----
aws cloudformation deploy --stack-name $Stack --template-file $built --region $Region `
    --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset --parameter-overrides `
    "FindingsTableName=$FindingsTable" "CreateFindingsTable=$CreateTable" "ExistingFindingsStreamArn=$StreamArn" `
    "DecisionLogBucket=$DecisionLogBucket" "CreateDecisionLogBucket=$CreateBucket" `
    "TopicName=$TopicName" "CreateTopic=$CreateTopic" "NotificationEmail=$NotificationEmail" `
    "DecisionLogRetentionDays=$RetentionDays" "DecisionLogLockMode=$LockMode" "AgentRuntimeArn=$RuntimeArn"
if ($LASTEXITCODE -ne 0) { throw "deploy failed (exit $LASTEXITCODE); see the stack events in the CloudFormation console" }

# ---- outputs ----
$out = @{}
(aws cloudformation describe-stacks --stack-name $Stack --region $Region --query "Stacks[0].Outputs" --output json |
    ConvertFrom-Json) | ForEach-Object { $out[$_.OutputKey] = $_.OutputValue }

Write-Host ""
Write-Host "For local runs, put these in .env:"
Write-Host "  AWS_REGION=$Region"
Write-Host "  FINDINGS_TABLE=$($out.FindingsTableName)"
Write-Host "  DECISION_LOG_BUCKET=$($out.DecisionLogBucket)"
Write-Host "  DECISION_LOG_RETENTION_DAYS=$($out.DecisionLogRetentionDays)"
Write-Host "  DECISION_LOG_LOCK_MODE=$($out.DecisionLogLockMode)"
Write-Host "  FINDINGS_TOPIC_ARN=$($out.FindingsTopicArn)"
Write-Host "  High_Critical_Queue_Url=$($out.HighCriticalQueueUrl)"
Write-Host ""
if ($RuntimeArn) {
    Write-Host "Invoker connected to $RuntimeArn. The pipeline is complete."
} else {
    Write-Host "Next: .\deploy\deploy_runtime.ps1, then rerun this script to add the invoker Lambda."
}
if ($NotificationEmail -and $CreateTopic -eq "true") {
    Write-Host "Confirm the subscription email AWS sent to $NotificationEmail."
}
