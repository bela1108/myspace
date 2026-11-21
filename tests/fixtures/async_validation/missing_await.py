async def verify_payload(payload):
    return payload == "trusted"


def handle(payload):
    if verify_payload(payload):
        return "allowed"
    return "denied"
