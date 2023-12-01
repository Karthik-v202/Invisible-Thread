from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def encrypt(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    encrypted_text = b64encode(ciphertext).decode("utf-8")
    return b64encode(salt).decode("utf-8") + iv + encrypted_text

def decrypt(encrypted_message, password):
    salt = b64decode(encrypted_message[:24])
    iv = b64decode(encrypted_message[24:48])
    ciphertext = b64decode(encrypted_message[48:])
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32)
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")
        return decrypted_text
    except (ValueError, KeyError):
        return "Incorrect password"

def main_win():
    def encrypt_message():
        message = enter1.get("1.0", END).strip()
        password = password_field.get()
        encrypted_message = encrypt(message, password)
        enter1.delete("1.0", END)
        password_field.delete(0, END)
        enter2.delete(0, END)
        enter2.insert(END, encrypted_message)

    def decrypt_message():
        encrypted_message = enter1.get("1.0", END).strip()
        password = password_field.get()
        decrypted_message = decrypt(encrypted_message, password)
        enter1.delete("1.0", END)
        password_field.delete(0, END)
        enter2.delete(0, END)
        enter2.insert(END, decrypted_message)

    win = Tk()
    win.title("ASCII CONVERTER")
    win.config(bg="Black")
    win.geometry("500x600")
    win.resizable(False, False)
    
    label1 = Label(win, text="Enter Message", font=("Times New Roman", 20, "bold"), bg="Black", fg="lime")
    label1.place(x=20, y=20, height=50, width=170)

    enter1 = Text(win, font=("Times New Roman", 15))
    enter1.place(x=20, y=60, height=150, width=450)

    label2 = Label(win, text="Enter Password", font=("Times New Roman", 20, "bold"), bg="Black", fg="lime")
    label2.place(x=20, y=210, height=50, width=180)

    password_var = StringVar()
    password_field = Entry(win, show="*", font=("Times New Roman", 15), textvariable=password_var)
    password_field.place(x=20, y=250, height=50, width=450)

    en = Button(win, text="Encrypt", font=("Time New Roman", 20), bg="Navy blue", fg="lime", command=encrypt_message)
    en.place(x=20, y=320, height=50, width=200)

    en2 = Button(win, text="Decrypt", font=("Time New Roman", 20), bg="Navy blue", fg="lime", command=decrypt_message)
    en2.place(x=285, y=320, height=50, width=200)

    label3 = Label(win, text="Result", font=("Times New Roman", 20, "bold"), bg="Black", fg="lime")
    label3.place(x=15, y=380, height=50, width=170)

    enter2 = Entry(win, font=("Times New Roman", 15))
    enter2.place(x=20, y=420, height=150, width=450)

    win.mainloop()

main_win()
