"""
Title: Graphical user interface for credentials.py
Author: Unknown - Edited by Group
Date: 19-02-2019

Current issues:
- Some lines (25-40) do not follow PEP8. These need to be shortened
"""

import tkinter as gui
import tkinter.ttk


class UIMain(gui.Frame):
    """
    Main GUI class
    """
    def __init__(self, master=None):
        """
        Constructor method
        :param master: Parent widget to be passed into a new instance of Application
        """
        super().__init__(master)
        self.master = master
        self.filepath_title = gui.Label(master, text="Load File", font=('Helvetica', 16, 'bold')).grid(row=1, column=1, sticky="w", pady=4)
        self.filepath_label = gui.Label(master, text="Enter Filename", font=('Helvetica', 10)).grid(row=2, column=1)
        self.filepath_input = gui.Entry(root).grid(row=2, column=2, padx=20)
        self.file_load_button = gui.Button(root, text="Load File", font=('Helvetica', 8)).grid(row=2, column=3)
        self.filepath_error = gui.Label(root, text="", fg="red", font=('Helvetica', 8)).grid(row=3, column=2)
        self.line_break = gui.ttk.Separator(root, orient="horizontal").grid(row=4, columnspan=4, sticky="ew")
        self.create_account_title = gui.Label(master, text="Create Account", font=('Helvetica', 16, 'bold')).grid(row=5, column=1, sticky="w", pady=4)
        self.username_label = gui.Label(root, text="Username", font=('Helvetica', 10)).grid(row=6, column=1)
        self.username_input = gui.Entry(root).grid(row=6, column=2)
        self.username_error = gui.Label(root, text="", fg="red", font=('Helvetica', 8)).grid(row=7, column=2)
        self.password_label = gui.Label(root, text="Password", font=('Helvetica', 10)).grid(row=8, column=1)
        self.password_input = gui.Entry(root).grid(row=8, column=2)
        self.password_error = gui.Label(root, text="", fg="red", font=('Helvetica', 8)).grid(row=9, column=2)
        self.password_confirmation_label = gui.Label(root, text="Confirm Password", font=('Helvetica', 10)).grid(row=10, column=1)
        self.password_confirmation_input = gui.Entry(root).grid(row=10, column=2)
        self.password_confirmation_error = gui.Label(root, text="", fg="red", font=('Helvetica', 8)).grid(row=11, column=2)
        self.clear = gui.Button(root, text="Clear", font=('Helvetica', 8)).grid(row=12, column=1)
        self.submit = gui.Button(root, text="Submit", font=('Helvetica', 8)).grid(row=12, column=2)


root = gui.Tk()
ui = UIMain(master=root)
ui.master.title("Account Creator")
ui.master.geometry("390x285")
ui.master.resizable(0, 0)
ui.mainloop()
