from __future__ import annotations


class JWK:
    def import_key(self, key_data: dict[str, str]) -> JWK:
        try:
            key_type = key_data["kty"]
        except KeyError as exc:
            msg = "The key type is not specified in the JWK."
            raise ValueError(msg) from exc

        if key_type == "EC":
            return ECKey(key_data)

        if key_type == "RSA":
            return RSAKey(key_data)

        msg = f"Unsupported key type: {key_type}"
        raise ValueError(msg)


class ECKey(JWK):
    def __init__(self, key_data: dict[str, str]) -> None:
        pass


class RSAKey(JWK):
    def __init__(self, key_data: dict[str, str]) -> None:
        pass
