from tkinter import *
from tkinter import filedialog  # 显式导入 filedialog 子模块
from ttkbootstrap import *
from ttkbootstrap.dialogs import *
import base64

from easycrypto import *

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 加密解密工具")
        self._setup_window()
        self.notebook = self._create_notebook()
        self._create_text_tab()
        self._create_file_tab()

    def _setup_window(self):
        """设置窗口大小、位置和图标"""
        window_size = (650, 480)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_size[0]) // 2
        y = (screen_height - window_size[1]) // 2
        self.root.geometry(f"{window_size[0]}x{window_size[1]}+{x}+{y}")

        icon_path = "icon_32x32.ico"
        try:
            self.root.iconbitmap(icon_path)
        except Exception as e:
            self._show_message("错误", f"设置图标失败: {str(e)}", kind="error")

    def _create_notebook(self):
        notebook = Notebook(self.root)
        notebook.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        return notebook

    def _create_tab(self, tab_text):
        tab = Frame(self.notebook)
        self.notebook.add(tab, text=tab_text)
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        return tab

    def _create_frame(self, parent, row=0, col=0, padx=4, pady=4, sticky="nsew"):
        frame = Frame(parent)
        frame.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        frame.grid_rowconfigure(99, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        return frame

    def _create_label(self, parent, text, font=None, row=0, col=0, pady=2, padx=2, sticky="w"):
        label = Label(parent, text=text, font=font)
        label.grid(row=row, column=col, pady=pady, padx=padx, sticky=sticky)
        return label

    def _create_text(self, parent, height=3, width=32, row=0, col=0, pady=2, padx=2, sticky="we"):
        text = Text(parent, height=height, width=width)
        text.grid(row=row, column=col, pady=pady, padx=padx, sticky=sticky)
        return text

    def _create_entry(self, parent, width=32, row=0, col=0, pady=2, padx=2, sticky="we"):
        entry = Entry(parent, width=width)
        entry.grid(row=row, column=col, pady=pady, padx=padx, sticky=sticky)
        return entry

    def _create_button(self, parent, text, command, row=0, col=0, pady=2, padx=2, sticky="we", bootstyle="default"):
        button = Button(parent, text=text, command=command, bootstyle=bootstyle)
        button.grid(row=row, column=col, pady=pady, padx=padx, sticky=sticky)
        return button

    def _show_message(self, title, message, kind="info"):
        """显示消息框"""
        if kind == "info":
            Messagebox.show_info(title=title, message=message, parent=self.root)
        elif kind == "error":
            Messagebox.show_error(title=title, message=message, parent=self.root)

    def _create_text_tab(self):
        """创建文本操作标签页"""
        text_tab = self._create_tab("文本操作")
        text_tab.grid_rowconfigure(0, weight=1)
        text_tab.grid_columnconfigure(0, weight=1)
        text_tab.grid_columnconfigure(1, weight=1)

        # 文本加密框架（左栏）
        encrypt_frame = self._create_frame(text_tab, row=0, col=0, sticky="nsew", padx=4, pady=4)
        encrypt_frame.grid_rowconfigure(99, weight=1)
        encrypt_frame.grid_columnconfigure(0, weight=1)

        self._create_label(encrypt_frame, "文本加密", font=("Arial", 12, "bold"), row=0, col=0, sticky="ew", pady=0, padx=0)
        self.plaintext_entry = self._create_text(encrypt_frame, row=1, col=0, height=3, sticky="ew", pady=1, padx=1)
        self.encrypt_text_btn = self._create_button(
            encrypt_frame, "加密文本", self.encrypt_text, row=2, col=0, bootstyle="primary", sticky="ew", pady=1, padx=1
        )
        self._create_label(encrypt_frame, "加密后的文本:", row=3, col=0, sticky="ew", pady=1, padx=1)
        self.encrypted_text_display = self._create_text(encrypt_frame, row=4, col=0, height=2, sticky="ew", pady=1, padx=1)
        self.encrypted_text_display.config(state=DISABLED)
        Button(encrypt_frame, text="复制", command=lambda: self.copy_text(self.encrypted_text_display)).grid(row=5, column=0, sticky="ew", padx=1, pady=1)
        self._create_label(encrypt_frame, "生成的密钥:", row=6, col=0, sticky="ew", pady=1, padx=1)
        self.key_display = self._create_text(encrypt_frame, row=7, col=0, height=2, sticky="ew", pady=1, padx=1)
        self.key_display.config(state=DISABLED)
        Button(encrypt_frame, text="复制", command=lambda: self.copy_text(self.key_display)).grid(row=8, column=0, sticky="ew", padx=1, pady=1)

        # 文本解密框架（右栏）
        decrypt_frame = self._create_frame(text_tab, row=0, col=1, sticky="nsew", padx=4, pady=4)
        decrypt_frame.grid_rowconfigure(99, weight=1)
        decrypt_frame.grid_columnconfigure(0, weight=1)

        self._create_label(decrypt_frame, "文本解密", font=("Arial", 12, "bold"), row=0, col=0, sticky="ew", pady=0, padx=0)
        self.encrypted_text_entry = self._create_text(decrypt_frame, row=1, col=0, sticky="ew")
        self._create_label(decrypt_frame, "输入密钥:", row=2, col=0, sticky="ew")
        self.key_text_entry = self._create_entry(decrypt_frame, row=3, col=0, sticky="ew")
        self.decrypt_text_btn = self._create_button(
            decrypt_frame, "解密文本", self.decrypt_text, row=4, col=0, bootstyle="primary", sticky="ew"
        )
        self._create_label(decrypt_frame, "解密后的文本:", row=5, col=0, sticky="ew")
        self.decrypted_text_display = self._create_text(decrypt_frame, row=6, col=0, height=3, sticky="ew")
        self.decrypted_text_display.config(state=DISABLED)
        Button(decrypt_frame, text="复制", command=lambda: self.copy_text(self.decrypted_text_display)).grid(row=7, column=0, sticky="ew", padx=1, pady=1)

    def decrypt_text(self):
        encrypted_text = self.encrypted_text_entry.get("1.0", "end-1c").strip()
        key = self.key_text_entry.get().strip()
        if not encrypted_text or not key:
            self._show_message("错误", "请输入加密文本和密钥", kind="error")
            return
        try:
            crypto = Crypto(key=base64.b64decode(key))
            # 传入 key 参数
            decrypted_text = crypto.decrypt_text(encrypted_text, key)
            if decrypted_text:
                self.decrypted_text_display.config(state=NORMAL)
                self.decrypted_text_display.delete("1.0", "end")
                self.decrypted_text_display.insert("1.0", decrypted_text)
                self.decrypted_text_display.config(state=DISABLED)
                self._show_message("解密成功", "解密成功，结果已显示在下方文本框中")
            else:
                self._show_message("解密失败", "解密过程中出现错误，请检查输入", kind="error")
        except Exception as e:
            self._show_message("解密失败", f"解密过程中出现错误: {str(e)}，请检查输入", kind="error")

    def _create_file_tab(self):
        file_tab = self._create_tab("文件操作")
        file_tab.grid_rowconfigure(0, weight=1)
        file_tab.grid_columnconfigure(0, weight=1)
        file_tab.grid_columnconfigure(1, weight=1)

        # 文件加密框架（左栏）
        encrypt_frame = self._create_frame(file_tab, row=0, col=0, sticky="nsew", padx=4, pady=4)
        encrypt_frame.grid_rowconfigure(99, weight=1)
        encrypt_frame.grid_columnconfigure(0, weight=1)

        self._create_label(encrypt_frame, "文件加密", font=("Arial", 12, "bold"), row=0, col=0, sticky="ew")
        self.encrypt_file_btn = self._create_button(
            encrypt_frame, "选择文件加密", self.encrypt_file, row=1, col=0, bootstyle="primary", sticky="ew"
        )
        self._create_label(encrypt_frame, "生成的密钥:", row=2, col=0, sticky="ew")
        self.file_encrypt_key_display = self._create_text(encrypt_frame, row=3, col=0, height=2, sticky="ew")
        self.file_encrypt_key_display.config(state=DISABLED)
        Button(encrypt_frame, text="复制", command=lambda: self.copy_text(self.file_encrypt_key_display)).grid(row=4, column=0, sticky="ew", padx=1, pady=1)

        # 文件解密框架（右栏）
        decrypt_frame = self._create_frame(file_tab, row=0, col=1, sticky="nsew", padx=4, pady=4)
        decrypt_frame.grid_rowconfigure(99, weight=1)
        decrypt_frame.grid_columnconfigure(0, weight=1)

        self._create_label(decrypt_frame, "文件解密", font=("Arial", 12, "bold"), row=0, col=0, sticky="ew")
        self._create_label(decrypt_frame, "输入密钥:", row=1, col=0, sticky="ew")
        self.key_file_entry = self._create_entry(decrypt_frame, row=2, col=0, sticky="ew")
        self.decrypt_file_btn = self._create_button(
            decrypt_frame, "选择文件解密", self.decrypt_file, row=3, col=0, bootstyle="primary", sticky="ew"
        )

    def encrypt_text(self):
        plaintext = self.plaintext_entry.get("1.0", "end-1c").strip()
        if not plaintext:
            self._show_message("错误", "请输入要加密的文本", kind="error")
            return
        crypto = Crypto()
        encrypted_text, key = crypto.encrypt_text(plaintext)

        self.encrypted_text_display.config(state=NORMAL)
        self.encrypted_text_display.delete("1.0", "end")
        self.encrypted_text_display.insert("1.0", encrypted_text)
        self.encrypted_text_display.config(state=DISABLED)

        self.key_display.config(state=NORMAL)
        self.key_display.delete("1.0", "end")
        self.key_display.insert("1.0", key)
        self.key_display.config(state=DISABLED)

    def copy_text(self, text_widget):
        # 只读模式下临时切换为NORMAL读取内容
        state = text_widget.cget("state")
        text_widget.config(state=NORMAL)
        result = text_widget.get("1.0", "end-1c").strip()
        text_widget.config(state=state)
        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self._show_message("复制成功", "内容已复制到剪贴板")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        crypto = Crypto()
        encrypted_file_path, key = crypto.encrypt_file(file_path)
        self.file_encrypt_key_display.config(state=NORMAL)
        self.file_encrypt_key_display.delete("1.0", "end")
        self.file_encrypt_key_display.insert("1.0", key)
        self.file_encrypt_key_display.config(state=DISABLED)
        # 确保密钥显示后再弹出提示框
        self.root.update_idletasks()
        self._show_message("加密成功", f"文件加密成功，保存路径:\n{encrypted_file_path}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        key = self.key_file_entry.get().strip()
        if not file_path or not key:
            self._show_message("错误", "请选择文件并输入密钥", kind="error")
            return
        try:
            # 尝试解码密钥
            decoded_key = base64.b64decode(key)
            crypto = Crypto(key=decoded_key)
            decrypted_file_path = crypto.decrypt_file(file_path, key)
            if decrypted_file_path:
                self._show_message("解密成功", f"文件解密成功，保存路径:\n{decrypted_file_path}")
            else:
                self._show_message("解密失败", "解密过程中出现错误，请检查输入", kind="error")
        except Exception as e:
            self._show_message("解密失败", f"解密过程中出现错误: {str(e)}，请检查输入", kind="error")


if __name__ == "__main__":
    root = Window(themename="litera")
    app = CryptoApp(root)
    root.mainloop()