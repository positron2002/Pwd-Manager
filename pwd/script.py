import tkinter as tk
from tkinter import messagebox
import sqlite3
from cryptography.fernet import Fernet
import string
import secrets
import pyperclip
import os
# this is a test to verify that git is configured correctly
# Generate a key for AES encryption
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_key():
    try:
        return open("key.key", "rb").read()
    except FileNotFoundError:
        generate_key()
        return open("key.key", "rb").read()

# Function to create the database table if it doesn't exist
def create_table():
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (website TEXT, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

# Function to encrypt the password
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Function to decrypt the password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password


# Function to generate a secure password
def generate_password():
    length_entry = password_length_entry.get()
    if length_entry:
        length = int(length_entry)
        characters = string.ascii_letters + string.digits + string.punctuation
        secure_password = ''.join(secrets.choice(characters) for _ in range(length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, secure_password)
    else:
        messagebox.showerror("Error", "Please enter a valid password length.")


# Function to add a new password entry
def add_password():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    key = load_key()
    encrypted_password = encrypt_password(password, key)

    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute("INSERT INTO passwords VALUES (?, ?, ?)", (website, username, encrypted_password))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password added successfully!")

# Function to retrieve passwords based on website and username
def search_password():
    import tkinter.ttk as ttk  # Import ttk module

    # Create a new window for search results
    search_window = tk.Toplevel(root)
    search_window.title("Search Results")

    # Create labels and entry fields for website and username
    website_label = tk.Label(search_window, text="Website:")
    website_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
    website_entry = tk.Entry(search_window)
    website_entry.grid(row=0, column=1, padx=10, pady=5)

    username_label = tk.Label(search_window, text="Username:")
    username_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
    username_entry = tk.Entry(search_window)
    username_entry.grid(row=1, column=1, padx=10, pady=5)

    # Function to display search results
    def display_results():
        website = website_entry.get()
        username = username_entry.get()

        conn = sqlite3.connect('password_manager.db')
        c = conn.cursor()

        if website and username:
            c.execute("SELECT website, username, password FROM passwords WHERE website LIKE ? AND username LIKE ?", ('%' + website + '%', '%' + username + '%'))
        elif website:
            c.execute("SELECT website, username, password FROM passwords WHERE website LIKE ?", ('%' + website + '%',))
        elif username:
            c.execute("SELECT website, username, password FROM passwords WHERE username LIKE ?", ('%' + username + '%',))
        else:
            messagebox.showerror("Error", "Please enter a website name or username.")

        results = c.fetchall()
        conn.close()

        # Create a table to display search results
        table = ttk.Treeview(search_window, columns=("Website Name", "Username", "Password"), show="headings")
        table.heading("Website Name", text="Website Name")
        table.heading("Username", text="Username")
        table.heading("Password", text="Password")

        for result in results:
            decrypted_password = decrypt_password(result[2], load_key())
            table.insert("", "end", values=(result[0], result[1], decrypted_password))

        table.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

        # Function to copy password to clipboard
        def copy_password(event):
            selected_item = table.focus()
            password = table.item(selected_item)["values"][2]
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard.")

        # Bind double click event to copy password
        table.bind("<Double-1>", copy_password)

    # Create search button
    search_button = tk.Button(search_window, text="Search", command=display_results)
    search_button.grid(row=2, column=1, padx=10, pady=5)

# Function to copy password to clipboard
def copy_password():
    password = password_entry.get()
    pyperclip.copy(password)
    messagebox.showinfo("Success", "Password copied to clipboard.")

# Function to set or verify master password
def set_master_password():
    master_password = master_password_entry.get()
    key = load_key()
    encrypted_master_password = encrypt_password(master_password, key)
    with open("master_password.txt", "wb") as file:
        file.write(encrypted_master_password)
    messagebox.showinfo("Success", "Master Password set successfully.")
    master_password_frame.grid_forget()
    login_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Function to check if master password is correct
def check_master_password():
    entered_password = master_password_entry.get()
    key = load_key()
    try:
        with open("master_password.txt", "rb") as file:
            encrypted_stored_password = file.read()
            stored_password = decrypt_password(encrypted_stored_password, key)
            if entered_password == stored_password:
                login_frame.grid_forget()
                main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
            else:
                messagebox.showerror("Error", "Incorrect Master Password.")
    except FileNotFoundError:
        master_password_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        login_frame.grid_forget()

# Create main window
root = tk.Tk()
root.title("Password Manager")

# Create frames
login_frame = tk.Frame(root)
login_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

master_password_frame = tk.Frame(root)

main_frame = tk.Frame(root)

# Create labels and entry fields for login
master_password_label = tk.Label(login_frame, text="Master Password:")
master_password_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

master_password_entry = tk.Entry(login_frame, show="*")
master_password_entry.grid(row=0, column=1, padx=10, pady=5)

# Create buttons for login
login_button = tk.Button(login_frame, text="Login", command=check_master_password)
login_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="we")

# Create labels and entry fields for setting master password
new_master_password_label = tk.Label(master_password_frame, text="Set Master Password:")
new_master_password_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

new_master_password_entry = tk.Entry(master_password_frame, show="*")
new_master_password_entry.grid(row=0, column=1, padx=10, pady=5)

# Create buttons for setting master password
set_master_password_button = tk.Button(master_password_frame, text="Set Password", command=set_master_password)
set_master_password_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="we")

# Create labels
website_label = tk.Label(main_frame, text="Website:")
website_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

username_label = tk.Label(main_frame, text="Username:")
username_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")

password_label = tk.Label(main_frame, text="Password:")
password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")

password_length_label = tk.Label(main_frame, text="Password Length:")
password_length_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")

# Create entry fields
website_entry = tk.Entry(main_frame)
website_entry.grid(row=0, column=1, padx=10, pady=5)

username_entry = tk.Entry(main_frame)
username_entry.grid(row=1, column=1, padx=10, pady=5)

password_entry = tk.Entry(main_frame, show="*")
password_entry.grid(row=2, column=1, padx=10, pady=5)

password_length_entry = tk.Entry(main_frame)
password_length_entry.grid(row=3, column=1, padx=10, pady=5)

# Create buttons
add_button = tk.Button(main_frame, text="Add Password", command=add_password)
add_button.grid(row=4, column=0, padx=10, pady=5, sticky="we")

search_button = tk.Button(main_frame, text="Search Password", command=search_password)
search_button.grid(row=4, column=1, padx=10, pady=5, sticky="we")

generate_button = tk.Button(main_frame, text="Generate Password", command=generate_password)
generate_button.grid(row=3, column=2, padx=10, pady=5, sticky="we")

copy_button = tk.Button(main_frame, text="Copy", command=copy_password)

# Create database table if it doesn't exist
create_table()

# Run the main event loop
root.mainloop()
