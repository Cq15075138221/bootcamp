import base64
import hashlib
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def find_pow_content(leading_zeros: int = 5) -> tuple[str, str, float]:
    target = "0" * leading_zeros
    nonce = 0
    started_at = time.perf_counter()

    while True:
        content = f"cg{nonce}"
        hash_value = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if hash_value.startswith(target):
            return content, hash_value, time.perf_counter() - started_at
        nonce += 1


def verify_signature(
    name: str,
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    content: bytes,
    signature: bytes,
) -> None:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise RuntimeError(f"{name} 签名验证失败") from error


def main() -> None:
    content, hash_value, elapsed = find_pow_content()
    message = content.encode("utf-8")

    print("符合 5 个前导零的 POW 内容：")
    print(f"Hash 内容：{content}")
    print(f"SHA-256：{hash_value}")
    print(f"搜索耗时：{elapsed:.6f} 秒")
    print()

    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_signature = rsa_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    verify_signature("RSA", rsa_private_key.public_key(), message, rsa_signature)
    print("RSA (2048 位, PSS + SHA-256)：")
    print(f"签名（Base64）：{base64.b64encode(rsa_signature).decode('ascii')}")
    print("公钥验证：成功")
    print()

    ecc_private_key = ec.generate_private_key(ec.SECP256R1())
    ecc_signature = ecc_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    verify_signature("ECC", ecc_private_key.public_key(), message, ecc_signature)
    print("ECC (P-256, ECDSA + SHA-256)：")
    print(f"签名（Base64）：{base64.b64encode(ecc_signature).decode('ascii')}")
    print("公钥验证：成功")


if __name__ == "__main__":
    main()
