import settings
from decouple import config
import dj_database_url

DEBUG = False
SECRET_KEY= config("SECRET_KEY")

DATABASES = {
    'default': dj_database_url.config(
        conn_max_age=600,
        conn_health_checks=True,
    ),
    
}
