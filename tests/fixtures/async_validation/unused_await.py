async def verify_payload(payload):
    return payload == "trusted"


async def handle(payload):
    await verify_payload(payload)
    return "allowed"
