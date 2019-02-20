"""
Title: Application to add records to a password file
Author: Unknown - Edited by Group
Date: 18-02-2019

Note:
Format for username and passwords file
username:password:salt
username2:password2:salt
"""

import hashlib
import random
import tkinter
import tkinter.ttk
import tkinter.scrolledtext

class Credentials:
    def __init__(self):
        self.cred_dict = {}
        self.file_path = "default.txt"

    def is_valid_username(self, user_name):
        """
        Prompt user for username, checking that a record doesn't already exist
        :param user_name: the requested username
        :return: bool
        """
        return len(user_name) > 0 and not self.cred_dict[user_name]

    @staticmethod
    def is_valid_password(password_orig, password_check):
        """
        Checks the password fields are not blank and that they match
        :param password_orig: first field value
        :param password_check: confirmation field value
        :return: boolean
        """
        return len(password_orig) > 0 and len(password_check) and password_orig == password_check

    @staticmethod
    def hash_password(pwd):
        """
        :param pwd: the plaintext password
        :return: tuple of (hashed password, salt)
        """

        salt = random.randint(1000, 1000000)
        hashed_password = hashlib.sha512(pwd + salt).hexdigest()

        return hashed_password, salt

    def load_credentials(self):
        """
        Reads credentials from file then stores them in a dictionary
        Assumes that the format for each line is
        username:password:salt
        Will record the latest duplicate entry and discard the others
        :param file_path: path to credentials file
        """

        try:
            with open(self.file_path, "r") as file:
                for line in file:
                    values = line.split(":")
                    self.cred_dict[values[0]] = values[1], values[2]
        except OSError as e:
            print("Could not read from file: {}".format(self.file_path))
            pass

    def output_credentials(self):
        """
        Open/Create file and output credentials
        """
        try:
            with open(self.file_path, "w") as f:
                for key, value in self.cred_dict.items():
                    f.write("{}:{}:{}".format(key, value[0], value[1]))
        except OSError as e:
            print("Could not write to file: {}".format(self.file_path))
            pass

    def add_to_dictionary(self, user, pwd, salt):
        """
        Simply adds the values to the dictionary, will replace an existing record with the same username

        :param user: username
        :param pwd: hashed password
        :param salt: the salt
        """
        self.cred_dict[user] = pwd, salt


class UI(tkinter.Frame):
    def set_file_path(self):
        # set file path in credentials
        if len(self.file_input.get()) > 0:
            self.credentials.file_path = self.file_input.get()
            self.credentials.load_credentials()
            print(self.credentials.cred_dict)
            self.debug_box.insert(tkinter.END, str(self.credentials.cred_dict))

    def __init__(self, master=None):
        super().__init__(master)
        self.credentials = Credentials()
        self.master = master
        self.file_caption = tkinter.Label(master, text="Load File", font="Helvetica 14")
        self.file_caption.grid(row=1, column=1, sticky="w")
        self.file_label = tkinter.Label(master, text="Filename")
        self.file_label.grid(row=2, column=1, sticky="w", padx=10)
        self.file_input = tkinter.Entry(master)
        self.file_input.grid(row=3, column=1, sticky="w", padx=10)
        self.file_button = tkinter.Button(master, text="Load", command=self.set_file_path)
        self.file_button.grid(row=3, column=2, sticky="w")
        self.separator = tkinter.ttk.Separator(master, orient="horizontal")
        self.separator.grid(row=4, column=1, columnspan=3, sticky="ew", pady=15, padx=10)

        self.account_caption = tkinter.Label(master, text="Create Account", font="Helvetica 14")
        self.account_caption.grid(row=5, column=1, sticky="w")
        self.username_label = tkinter.Label(master, text="Username")
        self.username_label.grid(row=6, column=1, sticky="w", padx=10)
        self.username_entry = tkinter.Entry(master)
        self.username_entry .grid(row=7, column=1, sticky="w", padx=10)
        self.password_label = tkinter.Label(master, text="Password")
        self.password_label.grid(row=8, column=1, sticky="w", padx=10)
        self.password_entry = tkinter.Entry(master)
        self.password_entry.grid(row=9, column=1, sticky="w", padx=10)
        self.confirm_label = tkinter.Label(master, text="Confirm Password")
        self.confirm_label.grid(row=10, column=1, sticky="w", padx=10)
        self.confirm_entry = tkinter.Entry(master)
        self.confirm_entry.grid(row=11, column=1, sticky="w", padx=10)
        self.save_button = tkinter.Button(master, text="Add Entry")
        self.save_button.grid(row=12, column=1, sticky="e", pady=10)
        self.clear_button = tkinter.Button(master, text="Clear")
        self.clear_button.grid(row=12, column=2, sticky="w", padx=10)
        self.debug_box = tkinter.scrolledtext.ScrolledText(master, width=20)
        self.debug_box.grid(row=13, column=1, columnspan=2, sticky="we")


root = tkinter.Tk()
root.geometry("200x400")
root.title("Account Creator")
app = UI(master=root)
app.mainloop()


