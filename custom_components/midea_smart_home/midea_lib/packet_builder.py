"""Midea Smart Home Packet Builder."""

from datetime import UTC, datetime
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .security import (
    LocalSecurity,
    ENCRYPT_TYPE_NONE,
    ENCRYPT_TYPE_AES_128,
    ENCRYPT_TYPE_AES_CCM,
    SIGN_TYPE_NONE,
    SIGN_TYPE_MD5
)


class PacketBuilder:
    """Packet builder."""

    def __init__(self, device_id: int, command: bytes) -> None:
        self.security = LocalSecurity()
        self.packet = bytearray(
            [
                0x5A, 0x5A, 0x01, 0x11, 0x00, 0x00, 0x20, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        )
        self.packet[12:20] = self._packet_time()
        self.packet[20:28] = device_id.to_bytes(8, "little")
        self.command = command

    def finalize(self, msg_type: int = 1, encrypt_type: int = ENCRYPT_TYPE_AES_128, sign_type: int = SIGN_TYPE_MD5) -> bytearray:
        if msg_type != 1:
            self.packet[3] = 0x10
            self.packet[6] = 0x7B
        else:
            # 添加加密类型和签名类型字节
            crypto_byte = (sign_type & 0xF0) | (encrypt_type & 0x0F)
            self.packet.append(crypto_byte)
            
            # 根据加密类型加密数据
            encrypted_data = self.security.encrypt_with_type(self.command, encrypt_type)
            self.packet.extend(encrypted_data)
        
        # 更新长度
        self.packet[4:6] = (len(self.packet) + 16).to_bytes(2, "little")
        
        # 生成签名
        if sign_type == SIGN_TYPE_MD5:
            salt = bytes.fromhex(
                format(
                    233912452794221312800602098970898185176935770387238278451789080441632479840061417076563,
                    "x",
                ),
            )
            self.packet.extend(md5(self.packet + salt).digest())
        else:
            # 无签名时添加 16 字节的占位符
            self.packet.extend(b"\x00" * 16)
        
        return self.packet

    @staticmethod
    def _packet_time() -> bytearray:
        t = datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S%f")[:16]
        b = bytearray()
        for i in range(0, len(t), 2):
            d = int(t[i : i + 2])
            b.insert(0, d)
        return b
