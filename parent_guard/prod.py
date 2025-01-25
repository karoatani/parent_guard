from settings import *
from decouple import config
import dj_database_url

DEBUG = False
SECRET_KEY= config("SECRET_KEY")

DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL')
    )
}
