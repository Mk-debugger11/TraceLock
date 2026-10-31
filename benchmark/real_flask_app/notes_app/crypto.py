from cryptography.fernet import Fernet, InvalidToken


class NoteCipher:
    """Notes are stored encrypted at rest with a Fernet key from the config."""

    def __init__(self, key):
        self._fernet = Fernet(key)

    def seal(self, text):
        return self._fernet.encrypt(text.encode("utf-8"))

    def unseal(self, token):
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken:
            return "[unreadable note]"
