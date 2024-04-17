import tkinter as tk
from tkinter import simpledialog, messagebox, font as tkfont
import sqlite3
import re
import bcrypt
import logging
import html
from logging.handlers import RotatingFileHandler

# Configure logging with rotation
log_formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
logFile = 'app.log'
my_handler = RotatingFileHandler(logFile, mode='a', maxBytes=5*1024*1024, backupCount=2, encoding=None, delay=0)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

app_logger = logging.getLogger('root')
app_logger.setLevel(logging.INFO)
app_logger.addHandler(my_handler)

# Initialize logging with a more detailed format and date/time stamp
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Initialize or update the database schema
def initialize_db():
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, email TEXT, password TEXT)''')
        conn.commit()
    logging.info("Database initialized")

# Input validation email
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Input validation name 
def validate_name(name):
    return re.match(r'^[A-Za-z ]+$', name) is not None

#Input validation age
def validate_age(age):
    return age.isdigit() and int(age) > 0

# Function to check if email already exists
def email_exists(email):
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute("SELECT EXISTS(SELECT 1 FROM users WHERE email=? LIMIT 1)", (email,))
        exists = c.fetchone()[0]
    return exists == 1

# CRUD operations with security considerations
def create_record(name, age, email, password):
    if email_exists(email):
        messagebox.showerror("Error", "Email already in use. Please use a different email.")
        logging.warning(f"Attempt to use existing email: {email}")
        return
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        with sqlite3.connect('crud_db.db') as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (name, age, email, password) VALUES (?, ?, ?, ?)", (name, age, email, hashed_password))
            conn.commit()
        messagebox.showinfo("Success", "Record added successfully!")
        logging.info(f"New record created for {email}")
    except sqlite3.IntegrityError as e:
        logging.error(f"Failed to create record for {email}. Error: {e}")
        messagebox.showerror("Error", "Failed to add record. Please try again.")

def read_records():
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, age, email FROM users")
        records = c.fetchall()
    return records
    pass

def read_records():
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, age, email FROM users")
        records = c.fetchall()
    return records
    pass

def update_record(id, name, age, email):
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET name = ?, age = ?, email = ? WHERE id = ?", (name, age, email, id))
        conn.commit()
    messagebox.showinfo("Success", "Record updated successfully!")
    logging.info(f"Record updated for ID: {id}")
    pass

def delete_record(id):
    with sqlite3.connect('crud_db.db') as conn:
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
    messagebox.showinfo("Success", "Record deleted successfully!")
    logging.info(f"Record deleted for ID: {id}")
    pass

# Display functions
def display_records():
    records = read_records()
    display_text = "\n".join([f"ID: {html.escape(str(record[0]))}, Name: {html.escape(record[1])}, Age: {html.escape(str(record[2]))}, Email: {html.escape(record[3])}" for record in records])
    messagebox.showinfo("All Records", display_text)
    pass

def update_existing_record():
    id = simpledialog.askstring("Update Record", "Enter the ID of the record to update:")
    name = simpledialog.askstring("Input", "Enter the new name:")
    age = simpledialog.askstring("Input", "Enter the new age:")
    email = simpledialog.askstring("Input", "Enter the new email:")
    if id and name and age and validate_email(email):
        update_record(id, name, age, email)
    else:
        messagebox.showerror("Error", "Invalid input.")
    pass

def delete_existing_record():
    id = simpledialog.askstring("Delete Record", "Enter the ID of the record to delete:")
    if id:
        delete_record(id)
    pass

# Add record function with input validation and password hashing
def add_record():
    name = name_entry.get()
    age = age_entry.get()
    email = email_entry.get()  
    password = password_entry.get()

# Check each input individually for more specific error feedback
    if not validate_name(name):
        messagebox.showerror("Error", "Invalid name. Please use alphabetic characters and spaces only.")
        logging.warning(f"Invalid name input: {name}")
        return
    if not validate_age(age):
        messagebox.showerror("Error", "Invalid age. Age must be a positive number.")
        logging.warning(f"Invalid age input: {age}")
        return
    if not validate_email(email):
        messagebox.showerror("Error", "Invalid email format. Please provide a valid email address.")
        logging.warning(f"Invalid email input: {email}")
        return
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        logging.warning("Attempt to create record without password.")
        return
    if email_exists(email):
        messagebox.showerror("Error", "Email already in use. Please use a different email.")
        logging.warning(f"Attempt to use existing email: {email}")
        return
    
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        with sqlite3.connect('crud_db.db') as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (name, age, email, password) VALUES (?, ?, ?, ?)", (name, age, email, hashed_password))
            conn.commit()
        messagebox.showinfo("Success", "Record added successfully!")
        logging.info(f"New record created for {email}")

    # Clear the input fields after adding the record
        name_entry.delete(0, tk.END)
        age_entry.delete(0, tk.END)
        email_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    except sqlite3.IntegrityError as e:
        logging.error(f"Failed to create record for {email}. Error: {e}")
        messagebox.showerror("Error", "Failed to add record. Please try again.")
    pass

# GUI setup for main app
def setup_main_app(root):
    global name_entry, age_entry, email_entry, password_entry
    
    # Font setup
    labelFont = tkfont.Font(size=12)
    entryFont = tkfont.Font(size=12)
    buttonFont = tkfont.Font(size=12)

    # Entry widgets
    tk.Label(root, text="Name:", font=labelFont).grid(row=0, column=0, padx=10, pady=5)
    tk.Label(root, text="Age:", font=labelFont).grid(row=1, column=0, padx=10, pady=5)
    tk.Label(root, text="Email:", font=labelFont).grid(row=2, column=0, padx=10, pady=5)
    tk.Label(root, text="Password:", font=labelFont).grid(row=3, column=0, padx=10, pady=5)

    name_entry = tk.Entry(root, font=entryFont)
    age_entry = tk.Entry(root, font=entryFont)
    email_entry = tk.Entry(root, font=entryFont)
    password_entry = tk.Entry(root, font=entryFont, show="*")

    name_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
    age_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
    email_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
    password_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    # Buttons
    tk.Button(root, text="Add Record", command=add_record, font=buttonFont).grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
    tk.Button(root, text="Show Records", command=display_records, font=buttonFont).grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
    tk.Button(root, text="Update Record", command=update_existing_record, font=buttonFont).grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
    tk.Button(root, text="Delete Record", command=delete_existing_record, font=buttonFont).grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
    
    # GUI setup
    root = tk.Tk()
    root.title("Secure CRUD Application")
    root.geometry("500x400")

def login_screen():
    def attempt_login():
        email = email_entry.get()
        password = password_entry.get()

        if validate_email(email) and password:
            with sqlite3.connect('crud_db.db') as conn:
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE email=?", (email,))
                db_password = c.fetchone()
                if db_password and bcrypt.checkpw(password.encode(), db_password[0]):
                    login_window.destroy()
                    main_app()  # Proceed to main application upon successful login
                else:
                    messagebox.showerror("Login Error", "Invalid email or password.")
        else:
            messagebox.showerror("Input Error", "Please provide valid email and password.")

    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Email:").pack()
    email_entry = tk.Entry(login_window)
    email_entry.pack()

    tk.Label(login_window, text="Password:").pack()
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack()

    tk.Button(login_window, text="Login", command=attempt_login).pack()

    login_window.mainloop()

def main_app():
    root = tk.Tk()
    root.title("Secure CRUD Application")
    root.geometry("500x400")
    setup_main_app(root)
    root.mainloop()

if __name__ == "__main__":
    initialize_db()
    login_screen()
