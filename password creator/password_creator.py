#passwword project


from cryptography.fernet import Fernet  
import os


#==========================This is the Welcome message==================================

print('Welcome to the Password Portal!\n\n')          
#This is where I encrypt your passwords

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
    with open('passwords.txt', "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, password = data.split('|')
            print('User:', user, "|" "Password:",
                  fer.decrypt(password.encode()).decode())
    with open('passwords.txt') as my_file:
            my_file.seek(0, os.SEEK_END)
            if my_file.tell():
                my_file.seek(0)
            else:
                print('File is empty...')

def add():                                  # This mode allows you to add an account to passwords.txt
    name = input('Account Name: ')
    password = input("Password: ")

    with open('passwords.txt', "a") as f:
        f.write(name + "|" + (fer.encrypt(password.encode())).decode() + '\n')

def remove():                                #This is the remove mode, it will allow you to delete all data in passwords.txt then will print the data in passwords.txt (there should be no data)
    f = open('passwords.txt', 'r+')
    f.truncate(0)


#==================================Main Menu============================================
while True:
    mode = input('Would you like to add a new password, view existing passwords, or remove all profiles and start fresh?\n (Add, View, Remove), or press q to quit: ').lower()
    if mode == 'q':             # This will exit / quit the program
        break
    if mode == "view":          # This is the view  mode, it shows the existing accounts logged in passwords.txt
        view()

    elif mode == "add":         # This mode allows you to add an account to passwords.txt
        add()

    elif mode == "remove":
        remove()
        print('You have successfully Removed all accounts from passwords.txt')
        def is_non_zero_file(fpath):  
            return os.path.isfile(fpath) and os.path.getsize(fpath) > 0
        view()
    else:
        print('Invalid Mode.')  # Invalid mode statement
        continue

#==================================Main Menu============================================