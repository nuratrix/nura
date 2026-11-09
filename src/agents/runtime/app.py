from bedrock_agentcore.runtime import BedrockAgentCoreApp

from agents.orchestrator.orchestrator_agent import handle_by_id

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload):
    finding_id = payload.get("finding_id")
    if not finding_id:
        return {"error": "finding_id is required"}
    try:
        return handle_by_id(finding_id)
    except LookupError as e:
        return {"error": str(e)}


if __name__ == "__main__":
    app.run()
