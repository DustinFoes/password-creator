import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)
#Databasse code

with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")


#initiate vault
vault = Tk() #creates a vault

vault.geometry('350x150') #defines the size of the vault in pixels
vault.title('Passwords Vault') #gives the vault a title
vault.config(background='black')
vault.resizable(False, False)

icon = PhotoImage(file= 'vault.png')
vault.iconphoto(True,icon)



#Create PopUp 
def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

#Initiate window
window = Tk()
window.update()

window.title("Password Vault")

def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1

def firstscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry('250x125')
    lbl = Label(vault, 
                text='Please Create Your Master Password:',
                bg='black',
                fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()


    txt = Entry(vault, 
                width=250,
                show='*')
    txt.pack()
    txt.focus()


    lbl1 = Label(vault,
                 text='Re-Enter Password',
                 bg='black',
                 fg='white')
    lbl1.pack()

    txt1 = Entry(vault, 
                width=250,
                show='*')
    txt1.pack()
    txt1.focus()


    

    def savepassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = '''INSERT INTO masterpassword(password)
            VALUES(?) '''
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            print(hashedPassword)
            passwordvault()
        else:
            lbl1.config(text='Passwords Do Not Match')
            txt.delete(0, 'end')
            txt1.delete(0, 'end')

    btn = Button(vault,
                 text='submit', 
                 command=savepassword)
    btn.pack(pady=10)


def getmasterpassword():
    checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
    curser.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
    print(checkHashedPassword)
    return cursor.fetchall()


    
def loginScreen():
    for widget in vault.winfo_children():
        widget.destroy()

    vault.geometry('250x125')

    lbl = Label(vault, text="Enter  Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(vault, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(vault)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            passwordvault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")
    
    def resetPassword():
        resetScreen()

    btn = Button(vault, text="Submit", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(vault, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)



    
    def add():
        for widget in vault.winfo_children():
            widget.destroy()
        lbl = Label(vault,
                    text='What Service is This For?')
        lbl.pack()
        txt = Entry (vault, 
                    width=20)

        txt.pack()

        btn2 = Button(vault,
                      text='Submit',
                      command=test)
    
        btn2.pack(pady=10)

def passwordvault():
    for widget in vault.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        passwordvault()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordvault()

    vault.geometry('750x550')
    vault.resizable(height=None, width=None)
    lbl = Label(vault, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(vault, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(vault, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(vault, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(vault, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl1 = Label(vault, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(vault, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(vault, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i+3))

            btn = Button(vault, text="Delete", command=  partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i+3), pady=10)

            i = i +1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

            
if cursor.fetchall():
    loginScreen()
else:
    firstscreen()













































#==========================This is the Welcome message==================================

'''print('Welcome to the Password Portal!\n\n')          
#This is where I encrypt your passwords
date = input('what is todays date? (use mm/dd/yy): ')
key = Fernet.generate_key()


#this is grabbing the master password originally set by the write_key function
def load_key():
    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    return key

master_password = input("What is your Master password?: ")
key = load_key() + master_password.encode()
fer = Fernet(key)

#This is where I encrypt your passwords


def view():                                 # This is the view  mode, it shows the existing accounts logged in passwords.txt
    print('\n\n\n')
    print('#####################################')
    with open('passwords.txt', "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, password, service = data.split('|')
            print('\n#  User:', user, "|" " Password:",
                  fer.decrypt(password.encode()).decode())
            print('Service: ', service)

    with open('passwords.txt') as my_file:
            my_file.seek(0, os.SEEK_END)
            if my_file.tell():
                my_file.seek(0)
            else:
                print('File is empty...')
    print('######################################')

def add():                                  # This mode allows you to add an account to passwords.txt
    service = input('What Service is the Account for?: ')
    name = input('Account Name: ')
    password = input("Password: ")
    with open('passwords.txt', "a") as f:
        f.write(name + "|" + (fer.encrypt(password.encode())).decode() + '|' + service + '\n')

def remove():                                #This is the remove mode, it will allow you to delete all data in passwords.txt then will print the data in passwords.txt (there should be no data)
    f = open('passwords.txt', 'r+')
    f.truncate(0)


#==================================Main Menu============================================

while True:
    mode = input('\n\n\nWould you like to add a new password, view existing passwords, or remove all profiles and start fresh?\n (Add, View, Remove), or press q to quit: ').lower()
    if mode == 'q':             # This will exit / quit the program
        break
    if mode == "vi6ew":          # This is the view  mode, it shows the existing accounts logged in passwords.txt
        view()
        print('\n\n\n')
    elif mode == "add":         # This mode allows you to add an account to passwords.txt
        add()
        print('\n\n\n')
    elif mode == "remove":
        remove()
        print('You have successfully Removed all accounts from passwords.txt')
        def is_non_zero_file(fpath):  
            return os.path.isfile(fpath) and os.path.getsize(fpath) > 0
        view()
        print('\n\n\n')
    else:
        print('Invalid Mode.\n\n\n')  # Invalid mode statement
        continue'''





#==================================Main Menu============================================
