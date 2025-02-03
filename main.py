import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from tkinter import *
from tkinter import filedialog, messagebox
from functools import partial

global filename
button_height = 2
button_width = 25

def browseFiles():
    browseFiles.filename = filedialog.askopenfilename(initialdir="/", title="Select a File")
    label_file_explorer.configure(text="File Opened: " + browseFiles.filename)

    pass_label.pack()
    password.pack()
    temp_label.pack()
    button_encrypt.pack()
    button_decrypt.pack()

def generate_key(password):
    """Generate a key from the given password using SHA-256."""
    hashed_password = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed_password)
#Encryption Process
def encrypt_file(password):
    try:
        key = generate_key(password.get())
        fernet = Fernet(key)

        with open(browseFiles.filename, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(browseFiles.filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        status_label.configure(text="File Encrypted Successfully")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found. Please select a valid file.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    finally:
        status_label.pack()
#Decryption process

def decrypt_file(password):
    try:
        key = generate_key(password.get())
        fernet = Fernet(key)

        with open(browseFiles.filename, 'rb') as enc_file:
            encrypted = enc_file.read()

        decrypted = fernet.decrypt(encrypted)

        with open(browseFiles.filename, 'wb') as dec_file:
            dec_file.write(decrypted)

        status_label.configure(text="File Decrypted Successfully")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found. Please select a valid file.")
    except InvalidToken:
        messagebox.showerror("Error", "Invalid key. Decryption failed.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    finally:
        status_label.pack()

# GUI Setup
window = Tk()
window.title('SafeCryptor')
window.geometry("940x740")
window.config(background="black")

main_title = Label(window, text="File Encryptor And Decryptor", width=100, height=2, fg="white", bg="black", font=("", 30))
passwd = StringVar()

submit_para_en = partial(encrypt_file, passwd)
submit_para_de = partial(decrypt_file, passwd)

credit = Label(window, text="Developed By MUNAF SHAIKH", bg="black", height=2, fg="white", font=("", 15))
label_file_explorer = Label(window, text="File Name : ", width=100, height=2, fg="white", bg="black", font=("", 20))
pass_label = Label(window, text="Password for encryption/decryption : ", width=100, height=2, fg="white", bg="black", font=("", 20))
temp_label = Label(window, text="", height=3, bg="black")

button_explore = Button(window, text="Browse File", command=browseFiles, width=button_width, height=button_height, font=("", 15))

password = Entry(window, textvariable=passwd, show="*")

button_encrypt = Button(window, text="Encrypt", command=submit_para_en, width=button_width, height=button_height, font=("", 15))
button_decrypt = Button(window, text="Decrypt", command=submit_para_de, width=button_width, height=button_height, font=("", 15))

status_label = Label(window, text="", width=100, height=4, fg="white", bg="black", font=("", 17))

footer = Label(window, text="©2K24_MunafShaikh. All rights reserved.", bg="black", fg="white", font=("", 10))

# Pack all elements
credit.pack()
main_title.pack()
label_file_explorer.pack()
button_explore.pack()
window.mainloop()
