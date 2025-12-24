import json
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Secret:
    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(key) != 16 and len(key) != 32:
            raise ValueError("key must be 16 or 32 bytes")
        if len(iv) != 16:
            raise ValueError("iv must be 16 bytes")
        self.key = key
        self.iv = iv


class UserSecret(Secret):

    def __init__(
        self, key_chars: str, iv_chars: str, guest_indices: str, user_indices: str = ""
    ) -> None:
        if len(guest_indices) < 16:
            raise ValueError("guest_indices must be at least 16 characters")

        self.key_chars = key_chars
        self.iv_chars = iv_chars
        self.guest_indices = guest_indices
        self.user_indices = user_indices.ljust(16, "0")

        self.generate_for()
        super().__init__(self.key, self.iv)

    def _generate(self, chars: str, indices: str) -> bytes:
        return "".join([chars[int(i)] for i in indices[:16]]).encode()

    def generate_for(self, user_id: str | None = None) -> None:
        if user_id is not None:
            indices = user_id + self.user_indices
        else:
            indices = self.guest_indices
        self.key = self._generate(self.key_chars, indices)
        self.iv = self._generate(self.iv_chars, indices)


class AESCipher:

    def __init__(self, secret: Secret) -> None:
        self.secret = secret

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.secret.key, AES.MODE_CBC, self.secret.iv)
        return cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.secret.key, AES.MODE_CBC, self.secret.iv)
        return unpad(cipher.decrypt(data), AES.block_size)


class B64Cipher(AESCipher):

    def __init__(self, secret: Secret) -> None:
        super().__init__(secret)

    def encrypt(self, data: str, no_colon=False) -> str:
        return b64encode(super().encrypt(data.encode())).decode() + (
            "" if no_colon else ":"
        )

    def decrypt(self, data: str, no_colon=False) -> str:
        return (
            super()
            .decrypt(b64decode((data if no_colon else data.split(":")[0])))
            .decode()
        )


class JsonCipher(B64Cipher):

    def __init__(self, secret: Secret) -> None:
        super().__init__(secret)

    def encrypt(self, data: dict, no_colon=False) -> str:
        return super().encrypt(json.dumps(data, separators=(",", ":")), no_colon)

    def decrypt(self, data: str, no_colon=False) -> dict:
        return json.loads(super().decrypt(data, no_colon))


class AES_ECB_Cipher:

    def __init__(self, secret: Secret) -> None:
        self.secret = secret

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.secret.key, AES.MODE_ECB)
        return cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.secret.key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size)


class B64_ECB_Cipher(AES_ECB_Cipher):

    def __init__(self, secret: Secret) -> None:
        super().__init__(secret)

    def encrypt(self, data: str, no_colon=False) -> str:
        return b64encode(super().encrypt(data.encode())).decode() + (
            "" if no_colon else ":"
        )

    def decrypt(self, data: str, no_colon=False) -> str:
        return (
            super()
            .decrypt(b64decode((data if no_colon else data.split(":")[0])))
            .decode()
        )


class Json_ECB_Cipher(B64_ECB_Cipher):

    def __init__(self, secret: Secret) -> None:
        super().__init__(secret)

    def encrypt(self, data: dict, no_colon=False) -> str:
        return super().encrypt(json.dumps(data, separators=(",", ":")), no_colon)

    def decrypt(self, data: str, no_colon=False) -> dict:
        return json.loads(super().decrypt(data, no_colon))


if __name__ == "__main__":

    # UserSecret is a subclass of Secret that uses specific guest and user indices
    secret = UserSecret("0917103641764451", "9171036417644515_82")
    cipher = JsonCipher(secret)

    # print the key and iv without any ID
    print("Key:", secret.key)
    print("IV:", secret.iv)

    # generate the key and iv with the user ID
    secret.generate("1766099")

    # print the key and iv with the user ID
    print("Key with ID:", secret.key)
    print("IV with ID:", secret.iv)

    data = "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:MTIzNDU2Nzg5MDEyMzQ1Ng=="

    data = cipher.decrypt(data)
    print(data)
