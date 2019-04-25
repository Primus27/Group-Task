"""
Title: Application to add records to a password file
Author: L3
Date: 18-02-2019

Note:
Format for username and passwords file
username:password:salt
"""

# Import statements
import hashlib
import base64
import secrets
import tkinter
import tkinter.ttk
import tkinter.scrolledtext
import tkinter.messagebox


class Credentials:
    """
    Stores all functions related to the backend of the UI.
    E.g. Checking validity of user input, hashing the password, etc.
    """

    def __init__(self):
        """
        Constructor method for default file name and credentials dictionary
        """

        self.cred_dict = {}
        self.file_path = "Default.txt"  # Default name

    def is_valid_username(self, user_name):
        """
        Prompt user for username, checking that a record doesn't already exist
        :param user_name: the requested username
        :return: boolean value as to whether the username is valid
        """

        # If the message isn't an error, a one will be returned for success
        to_return = 1

        # Conditions for validity. The username field cannot be empty, nor can it already exist in the dictionary
        if len(user_name) <= 0:
            to_return = "Username can't be empty."
        elif user_name in self.cred_dict:
            to_return = "Username already exists."

        return to_return

    @staticmethod
    def is_valid_password(password_orig, password_check):
        """
        Checks the password fields are not blank and that they match
        :param password_orig: first field value
        :param password_check: confirmation field value
        :return: boolean value as to whether the password is valid
        """

        # If the message isn't an error, a one will be returned for success
        to_return = 1

        # Conditions for validity. The password & confirmation cannot be empty, and both have to match
        if len(password_orig) <= 0:
            to_return = "Password can't be empty."
        elif len(password_check) <= 0:
            to_return = "Confirmation can't be empty."
        elif not password_orig == password_check:
            to_return = "Passwords don't match."

        return to_return

    @staticmethod
    def hash_password(pwd):
        """
        Generates a salt (securely) and uses both the salt and the password to create a hash
        :param pwd: the plaintext password
        :return: tuple of (hashed password, salt)
        """

        # Generate the salt. Using secrets is a safer and not repeatable unlike uuid
        salt = secrets.randbits(1024)

        # Hash (and salt) the password using a key derivation function. Convert to base 64 for readability
        hashed_password = hashlib.pbkdf2_hmac('sha512', str(pwd).encode("utf-8"), str(salt).encode("utf-8"), 100000, 64)
        b64_hashed_password = base64.b64encode(hashed_password)

        return b64_hashed_password, salt

    def load_credentials(self):
        """
        Reads credentials from file then stores them in a dictionary
        Assumes that the format for each line is
        username:password:salt
        Will record the latest duplicate record, previous duplicates are ignored
        :return: message on whether the file exists or if it will be created
        """

        # If the message isn't an error, a one will be returned for success
        to_return = 1

        # Attempt to load the file (read) and its values into a dictionary
        try:
            with open(self.file_path, "r") as file:
                for line in file:
                    values = line.replace("\n", "").split(":")
                    self.cred_dict[values[0]] = values[1], values[2]
        # If the file doesn't exist
        except OSError as e:
            to_return = e.strerror + ". File will be created once the form is completed."

        return to_return

    def output_credentials(self):
        """
        Open/Create file and output credentials
        :return: message on whether the dictionary was written to file
        """

        # If the message isn't an error, a one will be returned for success
        to_return = 1

        # Attempt to open the file for writing and output the username, password and key
        try:
            with open(self.file_path, "w") as f:
                for key, value in self.cred_dict.items():
                    f.write("{}:{}:{}\n".format(key, value[0], value[1]))
        # If the file cannot be written to (permissions...)
        except OSError as e:
            to_return = "Could not write to file: {}".format(self.file_path)

        return to_return

    def add_to_dictionary(self, user, pwd):
        """
        Hashes the password then adds the record to the dictionary
        :param user: username
        :param pwd: hashed password
        """

        # Call the hash function and output the hash & salt to the tied key in a dictionary
        password_and_salt = self.hash_password(pwd)
        self.cred_dict[user] = password_and_salt


class UI(tkinter.Frame):
    """
    Stores all UI related elements.
    E.g. buttons, txt input boxes, etc.
    """

    def set_file_path(self, silent=False):
        """
        Attempts to set the entered file path in the credentials object
        """

        # Once the file path is entered, see the returned message and output the correct info to the user
        if len(self.file_input.get()) > 0:
            self.credentials.file_path = self.file_input.get()
            load_message = self.credentials.load_credentials()
            if not load_message == 1:
                if not silent:  # On some occasions, the message will be echoed twice. This eliminates the issue
                    tkinter.messagebox.showerror("File could not be loaded", load_message)
            else:
                if not silent:
                    tkinter.messagebox.showinfo("Success", "File loaded")
        else:
            if not silent:
                tkinter.messagebox.showerror("Empty file string", "File path cannot be empty.")

    def save(self):
        """
        Validates user input, adds record to dictionary, then outputs to the stated file or Default.txt
        """

        # Check to see whether the username and password are valid
        validated = True # Assume valid until checks
        valid_username = self.credentials.is_valid_username(self.username_entry.get())
        valid_password = self.credentials.is_valid_password(self.password_entry.get(), self.confirm_entry.get())
        # If the username is invalid, output a useful error message
        if not valid_username == 1:
            tkinter.messagebox.showerror("Invalid username", valid_username)
            validated = False

        # If the password is invalid, output a useful error message
        elif not valid_password == 1:
            tkinter.messagebox.showerror("Invalid Password", valid_password)
            validated = False

        # If the input has been validated and no errors found, attempt to save the credentials
        if validated:
            self.credentials.add_to_dictionary(self.username_entry.get(), self.password_entry.get())
            if len(self.file_input.get()) > 0:
                self.set_file_path(True)

            save_message = self.credentials.output_credentials()

            # If the credentials couldn't be saved, output an error message
            if not save_message == 1:
                tkinter.messagebox.showerror("Could not output to specified file", save_message)
            # If the credentials have been saved, output an info message
            else:
                tkinter.messagebox.showinfo("Success", "The file saved successfully")
                self.clear()

    def clear(self):
        """
        Clears the account input fields
        """

        self.username_entry.delete(0, tkinter.END)
        self.password_entry.delete(0, tkinter.END)
        self.confirm_entry.delete(0, tkinter.END)

    def __init__(self, master=None):
        """
        Initialises the tkinter components
        :param master: A reference to parent window/frame (in this case, the root)
        """

        super().__init__(master)
        self.credentials = Credentials()
        self.master = master

        # Load file section
        self.file_caption = tkinter.Label(master, text="Load File", font="Helvetica 14")
        self.file_caption.grid(row=1, column=1, sticky="w")
        self.file_label = tkinter.Label(master, text="Filename")
        self.file_label.grid(row=2, column=1, sticky="w", padx=10)
        self.file_input = tkinter.Entry(master)
        self.file_input.insert(0, self.credentials.file_path)
        self.file_input.grid(row=3, column=1, sticky="w", padx=10)
        self.file_button = tkinter.Button(master, text="Load", command=self.set_file_path)
        self.file_button.grid(row=3, column=2, sticky="w")
        self.separator = tkinter.ttk.Separator(master, orient="horizontal")
        self.separator.grid(row=4, column=1, columnspan=3, sticky="ew", pady=15, padx=10)

        # Enter credentials section
        self.account_caption = tkinter.Label(master, text="Create Account", font="Helvetica 14")
        self.account_caption.grid(row=5, column=1, sticky="w")
        self.username_label = tkinter.Label(master, text="Username")
        self.username_label.grid(row=6, column=1, sticky="w", padx=10)
        self.username_entry = tkinter.Entry(master)
        self.username_entry.grid(row=7, column=1, sticky="w", padx=10)
        self.password_label = tkinter.Label(master, text="Password")
        self.password_label.grid(row=8, column=1, sticky="w", padx=10)
        self.password_entry = tkinter.Entry(master, show="*")
        self.password_entry.grid(row=9, column=1, sticky="w", padx=10)
        self.confirm_label = tkinter.Label(master, text="Confirm Password")
        self.confirm_label.grid(row=10, column=1, sticky="w", padx=10)
        self.confirm_entry = tkinter.Entry(master, show="*")
        self.confirm_entry.grid(row=11, column=1, sticky="w", padx=10)
        self.save_button = tkinter.Button(master, text="Add Entry", command=self.save)
        self.save_button.grid(row=12, column=1, sticky="e", pady=10)
        self.clear_button = tkinter.Button(master, text="Clear", command=self.clear)
        self.clear_button.grid(row=12, column=2, sticky="w", padx=10)


# Main application
root = tkinter.Tk()
root.geometry("200x300")  # Set window size
root.resizable(False, False)  # Prevent resizing of window
root.title("Accounts")  # Name the title bar
app = UI(master=root)
app.mainloop()  # Ensure that the UI is always running
