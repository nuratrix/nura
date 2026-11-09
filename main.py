"""AgentCore Runtime entrypoint: the container CMD and `agentcore configure -e main.py`.

Lives at the project root so the toolkit uses this folder (Dockerfile, pyproject, src/,
rulesets/) as the build context. The app itself is src/agents/runtime/app.py.
"""
from agents.runtime.app import app

if __name__ == "__main__":
    app.run()
