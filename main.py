import pyautogui
import webbrowser
import time
import keyboard
from tkinter import *
import imaplib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os.path

pyautogui.PAUSE = 0.4
#static_key = b'nnGBfWKikFc7i2OFhWNcgPBFdfIfFS0lwaFEYagaiwI='

def get_mails(mail_address, mail_pass):
  mail = imaplib.IMAP4_SSL('mail.bilkent.edu.tr')

  try:
    mail.login(mail_address, mail_pass)

  except:
    pyautogui.alert(text='mal doğru gir şifreni', title='helal', button='OK')
    return

  mail.list()
  mail.select("inbox")
  result, data = mail.search(None, "ALL")

  ids = data[0]
  id_list = ids.split()
  latest_email_id = id_list[-1]

  result, data = mail.fetch(latest_email_id, "(RFC822)")

  raw_email = data[0][1]
  return raw_email

def get_verification_code(raw_email):
    index = raw_email.find("Code: ")
    index += 6
    return raw_email[index : index + 5]

def on_closing():
    if(remember.get()):
        id_info = srsid.get()
        pass_info = srspass.get()
        mail_info = mail.get()
        mailpsw_info = mailpass.get()
        info_string = id_info + "\n" +pass_info + "\n" + mail_info + "\n" + mailpsw_info
        info_string_encoded = info_string.encode()

        if (len(id_info) == 0 or len(pass_info) == 0 or len(mail_info) == 0 or len(mailpsw_info) == 0):
            root.destroy()
            return

        password = pass_info.encode()  # Convert to type bytes
        salt = id_info.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

        f = Fernet(key)
        encrypted = f.encrypt(info_string_encoded)
        file = open('key.key', 'wb')
        file.write(key)
        file.write(encrypted)
        file.close()
        root.destroy()
    else:
        open('key.key', 'w').close()
        root.destroy()

def func(event):
    login()

def login():
    id_info = srsid.get()
    pass_info = srspass.get()
    mail_info = mail.get()
    mailpsw_info = mailpass.get()

    srsEntry.config(highlightbackground="white")
    passEntry.config(highlightbackground="white")
    mailEntry.config(highlightbackground="white")
    entry.config(highlightbackground="white")

    if (len(id_info) == 0):
        srsEntry.config(highlightbackground="red")
        return
    if (len(pass_info) == 0):
        passEntry.config(highlightbackground="red")
        return
    if (len(mail_info) == 0):
        mailEntry.config(highlightbackground="red")
        return
    if (len(mailpsw_info) == 0):
        entry.config(highlightbackground="red")
        return

    webbrowser.open('https://stars.bilkent.edu.tr/accounts/login')
    time.sleep(1)

    keyboard.write(id_info)
    pyautogui.hotkey('tab')
    time.sleep(0.5)
    keyboard.write(pass_info)
    time.sleep(0.5)

    pyautogui.hotkey('enter')
    time.sleep(1)
    raw_email = get_mails(mail_info+"@ug.bilkent.edu.tr", mailpsw_info)
    verification_code = get_verification_code(raw_email.decode("utf-8"))
    keyboard.write(verification_code)
    pyautogui.hotkey('enter')

    pyautogui.alert(text='bravo', title='helal', button='OK')

def show(event):
    passEntry['show'] = ""
def hide(event):
    passEntry['show'] = "*"
def show2(event):
    entry['show'] = ""
def hide2(event):
    entry['show'] = "*"

root = Tk()
root.title("SRS")
root.geometry("450x220")
root.eval('tk::PlaceWindow %s center' % root.winfo_pathname(root.winfo_id()))

if(os.path.exists('key.key') and os.path.isfile('key.key') and os.stat("key.key").st_size != 0):
    file = open("key.key", "rb")
    contents = file.read()
    key = contents[:44]
    message = contents[44:]
    f = Fernet(key)
    decrypted = f.decrypt(message)
    decoded = decrypted.decode("utf-8").split()

    srsid = StringVar(value=decoded[0])
    srspass = StringVar(value=decoded[1])
    mail = StringVar(value=decoded[2])
    mailpass = StringVar(value=decoded[3])
    remember = IntVar(value="1")
else:
    srsid = StringVar()
    srspass = StringVar()
    mail = StringVar()
    mailpass = StringVar()
    remember = IntVar()


Label(root,text="Bilkent ID",background="palegreen").grid(row=0,padx=5, pady=5)
srsEntry = Entry(root,width=15,textvariable=srsid)
srsEntry.grid(row=0, column=1,padx=5, pady=5)
srsEntry.focus()
Label(root,text="Stars Password",background="springgreen").grid(row=1,padx=5, pady=5)
passEntry = Entry(root, show='*',width=15,textvariable=srspass)
passEntry.default_show_val = passEntry['show']
passEntry['show'] = "*"
passEntry.grid(row=1, column=1,padx=5, pady=5)
button = Button(root,text="Show",cursor="gumby",fg="mediumseagreen")
button.bind('<ButtonPress-1>',show)
button.bind('<ButtonRelease-1>',hide)
button.grid(row=1,column=2,padx=5, pady=5)

Label(root,text="Webmail",background="lightseagreen").grid(row=2,padx=5, pady=5)
mailEntry = Entry(root,width=15,textvariable=mail)
mailEntry.grid(row=2, column=1,padx=5, pady=5)
Label(root,text="@ug.bilkent.edu.tr").grid(row=2, column=2,padx=5, pady=5)

Label(root,text="Webmail Password",background="lightgreen").grid(row=3,padx=5, pady=5)
entry = Entry(root,show='*',width=15,textvariable=mailpass)
entry.default_show_val = entry['show']
entry['show'] = "*"
entry.grid(row=3,column=1,padx=5, pady=5)
but = Button(root,text="Show",cursor="gumby",fg="mediumseagreen")
but.bind('<ButtonPress-1>',show2)
but.bind('<ButtonRelease-1>',hide2)
but.grid(row=3,column=2,padx=5, pady=0)

Button(root,text="Login",width=15, cursor="coffee_mug",command=login,fg="springgreen4",font=(None, 15)).grid(column=1)
Checkbutton(root,text="Remember Me",variable=remember).grid(column=1)

root.bind('<Return>', func)
root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
