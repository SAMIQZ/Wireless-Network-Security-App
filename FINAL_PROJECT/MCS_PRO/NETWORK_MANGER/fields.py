from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models

_fernet = Fernet(settings.ENCRYPTION_KEY)


class EncryptedCharField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 500)
        super().__init__(*args, **kwargs)

    def _encrypt(self, value):
        if value is None or value == '':
            return value
        return _fernet.encrypt(str(value).encode()).decode()

    def _decrypt(self, value):
        if value is None or value == '':
            return value
        try:
            return _fernet.decrypt(str(value).encode()).decode()
        except InvalidToken:
            return value

    def from_db_value(self, value, expression, connection):
        return self._decrypt(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return self._encrypt(value)