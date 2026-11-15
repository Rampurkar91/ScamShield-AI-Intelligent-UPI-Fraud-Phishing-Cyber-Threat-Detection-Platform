from pydantic_settings import BaseSettings, SettingsConfigDict
from urllib.parse import urlsplit

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str
    jwt_secret_key: str
    frontend_url: str = 'http://localhost:5173'
    environment: str = 'development'
    google_safe_browsing_api_key: str = ''
    virustotal_api_key: str = ''

    def validate_security(self):
        if len(self.jwt_secret_key) < 32 or 'replace-with' in self.jwt_secret_key:
            raise ValueError('JWT_SECRET_KEY must be a securely generated secret of at least 32 characters')
        if self.environment == 'production':
            if not self.database_url.startswith(('postgresql://', 'postgresql+psycopg://', 'postgres://')):
                raise ValueError('Production requires PostgreSQL DATABASE_URL')
            origins = self.frontend_url.split(',')
            for origin in origins:
                parsed = urlsplit(origin.strip())
                if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                        or parsed.path not in ('', '/') or parsed.query or parsed.fragment or '*' in parsed.netloc):
                    raise ValueError('Production FRONTEND_URL must contain HTTPS origins only, separated by commas')

settings = Settings()
settings.validate_security()
