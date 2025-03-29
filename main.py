from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

class Crypto:
    def __init__(self, password):
        """
        初始化 Crypto 类，密钥通过用户提供的密码派生。
        :param password: 用户提供的密码 (str)
        """
        # 使用 PBKDF2 从密码派生密钥
        salt = get_random_bytes(16)  # 生成随机盐
        self.key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=100000)
        self.salt = salt

    def AES_encrypt_text(self, plaintext):
        """
        加密文本。
        :param plaintext: 需要加密的文本 (str)
        :return: 加密后的 Base64 编码字符串 (str)
        """
        # 生成一个随机的初始化向量 (IV)
        iv = get_random_bytes(AES.block_size)

        # 创建 AES 加密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # 对文本进行填充并加密
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

        # 将盐、IV 和密文合并，并使用 Base64 编码以便传输或存储
        encrypted_data = self.salt + iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    def AES_decrypt_text(self, encrypted_data, password):
        """
        解密文本。
        :param encrypted_data: 加密后的 Base64 编码字符串 (str)
        :param password: 用户提供的密码 (str)
        :return: 解密后的文本 (str)
        """
        # 解码 Base64 数据
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))

        # 提取盐、IV 和密文
        salt = encrypted_data[:16]  # 前 16 字节是盐
        iv = encrypted_data[16:32]  # IV 长度为 16 字节
        ciphertext = encrypted_data[32:]

        # 使用密码和盐重新派生密钥
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=100000)

        # 创建 AES 解密器
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 解密并去除填充
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # 返回解密后的文本
        return plaintext.decode('utf-8')

    def AES_encrypt_file(self, input_file):
        """
        加密文件。
        :param input_file: 需要加密的文件路径 (str)
        :return: 加密后的文件输出路径 (str)
        """
        # 生成一个随机的初始化向量 (IV)
        iv = get_random_bytes(AES.block_size)

        # 创建 AES 加密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # 读取文件内容
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # 对文件内容进行填充并加密
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # 将盐、IV 和密文写入输出文件
        base_name, ext = os.path.splitext(input_file)
        output_file = f"{base_name}_encrypted{ext}"
        with open(output_file, 'wb') as f:
            f.write(self.salt + iv + ciphertext)

        return output_file

    def AES_decrypt_file(self, input_file, password):
        """
        解密文件。
        :param input_file: 需要解密的文件路径 (str)
        :param password: 用户提供的密码 (str)
        :return: 解密后的文件输出路径 (str)
        """
        # 读取加密文件内容
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        # 提取盐、IV 和密文
        salt = encrypted_data[:16]  # 前 16 字节是盐
        iv = encrypted_data[16:32]  # IV 长度为 16 字节
        ciphertext = encrypted_data[32:]

        # 使用密码和盐重新派生密钥
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=100000)

        # 创建 AES 解密器
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 解密并去除填充
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # 将解密后的内容写入输出文件
        base_name, ext = os.path.splitext(input_file)
        output_file = f"{base_name}_decrypted{ext}"
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        return output_file

# 示例用法
if __name__ == "__main__":
    os.system("title Crypto")

    print("1.加密文件")
    print("2.解密文件")
    op = input("请输入操作>>>")

    password = input("请输入密码>>>")

    if op == "1":
        # 加密文件示例
        input_file = input("请输入文件路径>>>")  # 需要加密的文件

        # 创建 Crypto 实例
        crypto = Crypto(password)

        # 加密文件
        encrypted_file = crypto.AES_encrypt_file(input_file)
        print(f"文件已加密并保存为: {encrypted_file}")

    elif op == "2":
        encrypted_file = input("请输入文件路径>>>")

        # 创建 Crypto 实例
        crypto = Crypto(password)

        # 解密文件
        decrypted_file = crypto.AES_decrypt_file(encrypted_file, password)
        print(f"文件已解密并保存为: {decrypted_file}")
    
    os.system("pause")