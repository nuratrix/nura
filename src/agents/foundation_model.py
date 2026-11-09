from strands.models import BedrockModel

def nova_pro():
    return BedrockModel(model_id="us.amazon.nova-pro-v1:0", temperature=0.1)