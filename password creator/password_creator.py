#passwword project


from cryptography.fernet import Fernet  
import os
from tkinter import *
import tkinter.messagebox
from tkinter import ttk
import sqlite3, hashlib

#Databasse code

with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL):
""")


#initiate window
vault = Tk() #creates a window

vault.geometry('350x150') #defines the size of the window in pixels
vault.title('Passwords Vault') #gives the window a title
vault.config(background='black')
vault.resizable(False, False)

icon = PhotoImage(file= 'vault.png')
vault.iconphoto(True,icon)


def firstscreen():

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
            hashedPassword = txt.get()

            insert_password = '''INSERT INTO masterpassword(password)
            VALUES(?) '''
            cursor.execute([insert_password, hashedPassword]) 
            db.commit

            passwordvault()
        else:
            lbl1.config(text='Passwords Do Not Match')
            txt.delete(0, 'end')
            txt1.delete(0, 'end')

    btn = Button(vault,
                 text='submit', 
                 command=savepassword)
    btn.pack(pady=10)
    
def LoginScreen():
    lbl = Label(vault, 
                text='Please Enter Your Master Password:',
                bg='black',
                fg='white')
    lbl.config(anchor=CENTER)
    lbl.pack()


    txt = Entry(vault, 
                width=10,
                show='*')
    txt.pack()
    txt.focus()

    lbl1 = Label(vault,
                 bg='black',
                 fg='white')
    lbl1.pack()

    def getmasterpassword():
        checkHashedPassword = txt.get()
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()


    def checkPassword():
        match = getmasterpassword

        if match():
            passwordvault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Password')

    btn = Button(vault, 
                 text='Submit',
                 command=checkPassword)
    btn.pack(pady=10)

def passwordvault():
    for widget in vault.winfo_children():
        widget.destroy()
    vault.geometry('700x350')

    lbl = Label(vault,
                text='Password Vault',
                font='Arial')
    lbl.config(anchor=CENTER)
    lbl.pack()

cursor.execute('SELECT * FROM masterpassword')
if cursor.fetchall():
    LoginScreen()
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
    if mode == "view":          # This is the view  mode, it shows the existing accounts logged in passwords.txt
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