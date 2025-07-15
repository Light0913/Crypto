"""
easycrypto.py 模块提供了基于 AES-EAX 模式的文本和文件加密解密功能。
支持生成随机密钥，对文本和文件进行加密，同时能使用给定密钥进行解密操作。
"""
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Crypto:
    def __init__(self, key=None):
        """
        初始化 Crypto 类，可选择传入密钥，若未传入则生成随机密钥。

        :param key: 加密解密使用的密钥，字节类型，默认为 None
        """
        if key:
            self.key = key
        else:
            self.key = get_random_bytes(32)

    def encrypt_text(self, plaintext):
        """
        使用 AES-EAX 模式加密文本。

        :param plaintext: 需要加密的文本，字符串类型
        :return: 加密后的 Base64 编码字符串和 Base64 编码的密钥，元组类型
        """
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        nonce = cipher.nonce
        encrypted_data = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        key_base64 = base64.b64encode(self.key).decode('utf-8')
        return encrypted_data, key_base64

    def decrypt_text(self, encrypted_text, key_base64):
        """
        使用 AES-EAX 模式解密文本。

        :param encrypted_text: 加密后的 Base64 编码字符串
        :param key_base64: Base64 编码的密钥
        :return: 解密后的文本，字符串类型；若解密失败则返回 None
        """
        try:
            key = base64.b64decode(key_base64)
            encrypted_data = base64.b64decode(encrypted_text)
            nonce, tag, ciphertext = self._parse_encrypted_data(encrypted_data)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_text.decode('utf-8')
        except (ValueError, KeyError) as e:
            print(f"Decryption error: {e}")
            return None

    def encrypt_file(self, file_path):
        """
        使用 AES-EAX 模式加密文件。

        :param file_path: 需要加密的文件路径，字符串类型
        :return: 加密后的文件路径和 Base64 编码的密钥，元组类型
        """
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        nonce = cipher.nonce
        encrypted_data = nonce + tag + ciphertext

        # 提取文件名和后缀
        file_name, file_ext = os.path.splitext(file_path)
        # 构造加密后的文件路径，添加 _encrypted 后缀
        encrypted_file_path = f"{file_name}_encrypted{file_ext}"

        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        key_base64 = base64.b64encode(self.key).decode('utf-8')
        return encrypted_file_path, key_base64

    def decrypt_file(self, file_path, key_base64):
        """
        使用 AES-EAX 模式解密文件。

        :param file_path: 需要解密的文件路径，字符串类型
        :param key_base64: Base64 编码的密钥
        :return: 解密后的文件路径，字符串类型；若解密失败则返回 None
        """
        try:
            key = base64.b64decode(key_base64)
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            nonce, tag, ciphertext = self._parse_encrypted_data(encrypted_data)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
            # 提取文件名和后缀
            file_name, file_ext = os.path.splitext(file_path)
            # 构造解密后的文件路径，添加 _decrypted 后缀
            decrypted_file_path = f"{file_name}_decrypted{file_ext}"

            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_text)
            return decrypted_file_path
        except (ValueError, KeyError) as e:
            print(f"Decryption error: {e}")
            return None

    def _parse_encrypted_data(self, encrypted_data):
        """
        解析加密数据，提取 nonce、tag 和 ciphertext。

        :param encrypted_data: 加密数据，字节类型
        :return: nonce、tag 和 ciphertext，元组类型
        """
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        return nonce, tag, ciphertext