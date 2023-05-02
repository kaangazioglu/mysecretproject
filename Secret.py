import tkinter as tk
from tkinter import *
from tkinter import messagebox
import base64



window = Tk()
window.title("Secret Notes")
window.minsize(width=500, height=700)

photo = tk.PhotoImage(file=r"C:\Users\PC\Desktop\secret\super_top_secret.png")
label_image = Label(image=photo)
label_image.pack()

label_line1 = Label(text="Enter Your Title", font=('Arial', 10, "bold"))
label_line1.pack()

entry_line = Entry(width=40)
entry_line.pack()

label_line2 = Label(text="Enter Your Secret", font=('Arial', 10, "bold"))
label_line2.pack()
label_line2.config(padx=10, pady=10)

my_text = Text(width=40, height=15)
my_text.pack()

label_line3 = Label(text="Enter Master Key", font=('Arial', 10, "bold"))
label_line3.pack()
label_line3.config(padx=10, pady=10)

entry_line2 = Entry(width=40)
entry_line2.pack()


def save_and_encrypt_notes():
    title = entry_line.get()
    message = my_text.get("1.0", END)
    master_secret = entry_line2.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info")
    else:
        message_encrypted = encode(master_secret, message)
        try:
            with open("secrett.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("secrett.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            entry_line.delete(0, END)
            my_text.delete("1.0", END)
            entry_line2.delete(0, END)


save_button = Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_button.pack()


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def decrypt_notes():
    message_encrypted = my_text.get("1.0", END)
    master_secret = entry_line2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            my_text.delete("1.0", END)
            my_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")





decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()

window.mainloop()
