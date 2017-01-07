# Django settings for access_web project.
import os

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

BASE_ROOT = ""

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': os.path.join(BASE_DIR, r'db.sqlite'),  # Or path to database file if using sqlite3.
    }
}

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/{{ docs_version }}/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'Europe/Paris'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-US'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '%s/static/' % BASE_ROOT

# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
ADMIN_MEDIA_PREFIX = '%s/static/admin/' % BASE_ROOT

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = '9uqo5d00h-l0a45!a6fq*e$y+lxw3&^34-#%18z4ci5^s1t3=o'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
# CACHES = {
# 'default': {
# 'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
# }
# }

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'djangooidc.backends.OpenIdConnectBackend',
)

LOGIN_URL = 'openid'

ROOT_URLCONF = 'django_rp.urls'

TEMPLATE_DIRS = (
    # os.path.join(BASE_DIR, "django_rp/templates"),
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Uncomment the next line to enable the admin:
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    'django.contrib.admindocs',

    'djangooidc',
    'testapp',
)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'INFO',
        },
        'oic': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'djangooidc': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
}

###############################################################################
# PyOIDC specific settings

# Check certificates? True by default.
# OIDC_VERIFY_SSL = True

# By default an internal user will be created for each new user that has successfully authenticate with OIDC.
# This can be disabled by setting this variable to False - in that case users must be manually referenced.
# OIDC_CREATE_UNKNOWN_USER = False

# The view for OIDC login uses a default template - it can be overridden here
# OIDC_LOGIN_TEMPLATE = "djangooidc/login.html"

# You may want to disable client registration. In that case, only the OP inside OIDC_PROVIDERS will be available.
# OIDC_ALLOW_DYNAMIC_OP = False

# Information used when dynamically registering a client on an OP.
# Ignored if auto registration is not used. May also be directly reused in OIDC_PROVIDERS (as this data may be
# the same for all OPs)
OIDC_DYNAMIC_CLIENT_REGISTRATION_DATA = {
    "application_type": "web",
    "contacts": ["ops@example.com"],
    "redirect_uris": ["http://localhost:8000/openid/callback", ],
    "post_logout_redirect_uris": ["http://localhost:8000/", ]
}

# Default is using the 'code' workflow, which requires direct connectivity from website to the OP.
OIDC_DEFAULT_BEHAVIOUR = {
    "response_type": "code",
    "scope": ["openid", "profile", "email", "address", "phone"],
}

# The keys in this dictionary are the OPs (OpenID Providers) short user friendly name not the issuer (iss) name.
OIDC_PROVIDERS = {
    # Test OP - webfinger supported on non-standard URL, no client self registration.
    "Azure Active Directory": {
        "srv_discovery_url": "https://sts.windows.net/84e34b3d-2101-4417-bc7a-6763baa47916/",
        "behaviour": OIDC_DEFAULT_BEHAVIOUR,
        "client_registration": {
            'client_id': "d6f9ad90-c6d1-4dfc-a7db-9e4ef4b524b2",
            "client_secret": "fGtyewgddjlim7zWtww7gypI/I/IwyylKBzvH/QVTDY=",
            "redirect_uris": ["http://localhost:8000/openid/callback/login/"],
            "post_logout_redirect_uris": ["http://localhost:8000/openid/callback/logout/"],
            "token_endpoint_auth_method": "client_secret_post"
        }
    },
    # # No webfinger support, but OP information lookup and client registration
    # "xenosmilus": {
    # "srv_discovery_url": "https://xenosmilus2.umdc.umu.se:8091/",
    # "client_info": ME,
    # "behaviour": BEHAVIOUR
    # },
    # # Supports OP information lookup but not client registration
    # "op.example.org": {
    # "srv_discovery_url": "https://example.org/op/discovery_endpoint",
    # "client_registration": {
    # "client_id": "abcdefgh",
    # "client_secret": "123456789",
    #         "redirect_uris": ["https://rp.example.com/authn_cb"],
    #     }
    # },
    # # Does not support OP information lookup but dynamic client registration
    # "noop.example.com": {
    #     "provider_info": {
    #         "issuer": "",
    #         "authorization_endpoint": "",
    #         "token_endpoint": "",
    #         "userinfo_endpoint": "",
    #         "registration_endpoint": "",
    #         "jwks_uri": "",
    #         "scopes_supported": "",
    #         "response_types_supported": "",
    #         "subject_types_supported": "",
    #         "id_token_signing_alg_values_supported": "",
    #         "claims_supported": "",
    #     },
    #     "client_info": ME,
    # },
    # # Does not support any dynamic functionality
    # "nodyn.example.com": {
    #     "provider_info": {
    #         "issuer": "",
    #         "authorization_endpoint": "",
    #         "token_endpoint": "",
    #         "userinfo_endpoint": "",
    #         "registration_endpoint": "",
    #         "jwks_uri": "",
    #         "scopes_supported": "",
    #         "response_types_supported": "",
    #         "subject_types_supported": "",
    #         "id_token_signing_alg_values_supported": "",
    #         "claims_supported": "",
    #     },
    #     "client_registration": {
    #         "client_id": "abcdefg",
    #         "client_secret": "123456789",
    #         "redirect_uris": ["https://rp.example.com/authn_cb"],
    #     }
    # },
}
#
###############################################################################