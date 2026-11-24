"""Safe: the exported object only ever carries public fields."""


def load_user(user_id):
    return {"name": "ada", "email": "ada@example.io",
            "password": "p@ss", "token": "tok-live"}


def export_profile(user_id, admin=False):
    user = load_user(user_id)
    public = {"name": user["name"]}
    if admin:
        public["email"] = user["email"]
    else:
        public["email"] = "hidden"
    snapshot = dict(public)
    return snapshot
