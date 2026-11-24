"""Reflow: a restricted field is written back into the exported copy."""


def fetch_account(user_id):
    return {"name": "ada", "email": "ada@example.io",
            "token": "tok-live", "password": "p@ss"}


def export_account(user_id, verbose=False):
    account = fetch_account(user_id)
    public = {"name": account["name"], "email": account["email"]}
    details = public
    if verbose:
        details["token"] = account["token"]
    return details
