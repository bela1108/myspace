async def verify_payload(payload):
    return payload == "trusted"


async def handle(payload):
    if await verify_payload(payload):
        return "allowed"
    return "denied"
