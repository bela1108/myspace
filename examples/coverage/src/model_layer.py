import os

MODEL_NAME = "tiny-transformer"


def load_model(weights_path):
    return {"name": MODEL_NAME, "path": os.path.abspath(weights_path)}
