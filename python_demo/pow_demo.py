import hashlib
import time


def mine(leading_zeros: int) -> None:
    target = "0" * leading_zeros
    nonce = 0
    started_at = time.perf_counter()

    while True:
        content = f"cg{nonce}"
        hash_value = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if hash_value.startswith(target):
            elapsed = time.perf_counter() - started_at
            print(f"满足 {leading_zeros} 个前导零：")
            print(f"花费时间：{elapsed:.6f} 秒")
            print(f"Hash 内容：{content}")
            print(f"Hash 值：{hash_value}")
            print()
            return
        nonce += 1


if __name__ == "__main__":
    mine(4)
    mine(5)
