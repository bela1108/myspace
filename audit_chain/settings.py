from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "dev-only-multi-database-audit-secret"
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "records",
]

MIDDLEWARE = []

ROOT_URLCONF = "audit_chain.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "business.sqlite3",
    },
    "archive": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "archive.sqlite3",
    },
}

DATABASE_ROUTERS = ["records.router.ExplicitOriginRouter"]

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
USE_TZ = True

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    }
]
