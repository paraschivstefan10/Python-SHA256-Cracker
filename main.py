                                ########## Author : Stefan-Cristian Paraschiv ##########
                                #                                             
                                #          Email: paraschivstefan20@gmail.com 
                                #      
                                ##########                                    ##########   
                                #                                                      #

import hashlib # For being able to create has values such as SHA256
import time # Library used as a part of assignment brief to allow the user to see how much time needed to crack a hash
import csv # Library used as a part of the assignment brief to allow to insert CSV files into the app to crack the hashes.
import re # Additional library to find pattern matching in strings 
import string # Additional library to allow to work with specific subsets of characters.
import tkinter as tk # Library used as a part of the assignment brief to allow the user to navigate on a GUI
from tkinter import filedialog, messagebox, scrolledtext, ttk #Tkinter widgets such as progression bar, text, allowing to type individual hashes or add a csv.
import threading # Important library used to prevent crashing because of lack of memory. Used so the app can run in parallel threads allwing a smooth GUI usage.

'''                          This app is a cohesive tool whereby a user can insert a
                     SHA256 hash via the command-line interface (CLI) or from a comma-separated values
            (CSV) file and then brute-force it to decrypt the plain text password or a GUI used with tkinter           '''



class HashCrackerApp:
    """
    A GUI-based application to crack SHA256 hashes using brute-force methods.

    Attributes
    ----------
    root : Tk
        Main application window.
    cracker_service : CrackerService
        Instance of CrackerService to handle hash cracking operations.
    hash_entry : Entry
        Input field for a SHA256 hash.
    output_display : ScrolledText
        Text area for displaying cracked hash results.
    """

    def __init__(self, root):
        """
        Initializes the HashCrackerApp with main window and sets up GUI widgets.

        Parameters
        ----------
        root : Tk
            The root window for the application.

        Side Effects
        ------------
        Initializes GUI elements and associates methods with button actions.
        """
        self.root = root
        self.root.title("Hash Cracker")
        self.cracker_service = CrackerService(self)
        self.setup_gui()

    def setup_gui(self):
        """
        Set up basic GUI elements.
        Side Effects
        ------------
        Creates and arranges buttons, labels, text areas, and other elements 
        in the root window.
        """
        tk.Label(self.root, text="Enter SHA256 Hash:").pack()
        self.hash_entry = tk.Entry(self.root, width=50)
        self.hash_entry.pack()

        tk.Button(self.root, text="Crack Single Hash", command=self.single_hash_crack).pack()
        tk.Button(self.root, text="Load CSV", command=self.load_hashes_from_csv).pack()
        tk.Button(self.root, text="Clear Output", command=self.clear_output).pack()

        self.progress_bar = ttk.Progressbar(self.root, mode='determinate', length=200)
        self.progress_bar.pack()

        self.output_display = scrolledtext.ScrolledText(self.root, width=60, height=20)
        self.output_display.pack()

    def single_hash_crack(self):
        """Handles cracking one hash from user input."""
        user_input_hash = self.hash_entry.get()
        if not self.cracker_service.is_valid_hash(user_input_hash):
            messagebox.showwarning("Invalid Entry", "Please enter a valid SHA256 hash.")
            return
        thread = threading.Thread(target=self.crack_hash_process, args=(user_input_hash,))
        thread.start()

    def crack_hash_process(self, hash_to_crack):
        """Cracks a given SHA256 hash using brute-force and updates the GUI.

        Parameters
        ----------
        hash_to_crack : str
            The SHA256 hash to crack.

        Side Effects
        ------------
        Updates progress bar and displays the result in the text area.
        """
        self.output_display.delete(1.0, tk.END)
        
        found_password, time_taken = self.cracker_service.brute_force_crack(hash_to_crack)

        if found_password:
            result_text = f"Hash: {hash_to_crack}\nPassword: {found_password}\nTime: {time_taken:.4f}s\n"
        else:
            result_text = "Password not found.\n"

        self.output_display.insert(tk.END, result_text)

    def load_hashes_from_csv(self):
        """Loads hashes from a CSV file and initiates cracking each one.

        Side Effects
        ------------
        Opens a file dialog to select a CSV file, then creates threads for 
        cracking each hash.
        """
        csv_file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if csv_file_path:
            threads = []
            # Accessing the method from CrackerService through self.cracker_service
            for target_hash in self.cracker_service.load_hashes_from_csv(csv_file_path): 
                self.output_display.insert(tk.END, f"Cracking: {target_hash}\n")
                self.root.update_idletasks()  # Keep the UI responsive
                thread = threading.Thread(target=self.crack_hash_process, args=(target_hash,))
                threads.append(thread)
                thread.start()

            # Wait for all threads to finish before showing the final message
            for thread in threads:
                thread.join()

            messagebox.showinfo("Complete", "Finished cracking all CSV hashes.")

    def clear_output(self):
        """
        Clears the hash entry and output display fields.

        Side Effects
        ------------
        Deletes content in the entry and output display areas.
        """
        self.hash_entry.delete(0, tk.END)
        self.output_display.delete(1.0, tk.END)

class CrackerService:
    """Manages the brute-force cracking and validation of SHA256 hashes.

    Attributes
    ----------
    app_reference : HashCrackerApp
        Reference to the HashCrackerApp instance, used for updating GUI components.
    """

    def __init__(self, app):
        """
        Initializes CrackerService with a reference to the main app instance.

        Parameters
        ----------
        app : HashCrackerApp
            The main application instance for updating the progress bar.
        """
        self.app_reference = app

    @staticmethod
    def hash_string(input_string):
        """Hashes a given string using SHA256.

        Parameters
        ----------
        input_string : str
            The string to hash.

        Returns
        -------
        str
            The SHA256 hash of the input string.
        """
        return hashlib.sha256(input_string.encode()).hexdigest()

    @staticmethod
    def is_valid_hash(hash_input):
        """Validates that the input string is a SHA256 hash.

        Parameters
        ----------
        hash_input : str
            The string to validate.

        Returns
        -------
        bool
            True if the input is a valid SHA256 hash, otherwise False.
        """
        return bool(re.fullmatch(r'[a-fA-F0-9]{64}', hash_input))
    
    def load_hashes_from_csv(self, csv_path):
        """Reads a CSV file and pulls out valid SHA256 hashes.

        Parameters
        ----------
        csv_path : str
            The path to the CSV file you want to load.

        Returns
        -------
        list
            A list of SHA256 hashes that were successfully read from the file.

        Side Effects
        ------------
        Shows error messages if the file is missing or if there are problems reading it.
        """
        hashes = []
        try:
            with open(csv_path, newline='') as csvfile:
                csv_reader = csv.DictReader(csvfile)
                for row in csv_reader:
                    if 'hash' in row and self.is_valid_hash(row['hash']):
                        hashes.append(row['hash'])
                    else:
                        print("Invalid hash format in CSV row, skipping.")
        except FileNotFoundError:
            messagebox.showerror("File Error", "CSV file not found.")
        except csv.Error as csv_err:
            messagebox.showerror("File Error", f"CSV format issue: {csv_err}")
        return hashes

    def brute_force_crack(self, hash_target, max_len=5):
        """Tries to figure out the original text that created a given SHA256 hash by testing every possible combination.

        Parameters
        ----------
        hash_target : str
            The hash you're trying to crack (must be a valid SHA256 hash).
        max_len : int, optional
            The maximum length of text combinations to try (default is 5).

        Returns
        -------
        tuple
            Returns a pair: (password, time_taken). If the password is found, you get it and how long it took. 
            If not, it returns (None, None).

        Side Effects
        ------------
        While running, this function updates the progress bar in the GUI so you can see how far along it is.
        """
    def brute_force_crack(self, target_hash, max_len=5):
        charset = string.ascii_letters + string.digits + string.punctuation
        start_time = time.time()
    
        def attempt_guess(prefix, processed_count):
            if len(prefix) > max_len:
                return None
        
            hashed_guess = self.hash_string(prefix)
            if hashed_guess == target_hash:
                return prefix
        
            for char in charset:
                result = attempt_guess(prefix + char, processed_count + 1)
                if result is not None:
                    return result
        
            return None
    
        result = attempt_guess("", 0)
        time_taken = time.time() - start_time
        return result, time_taken


    def attempt_guess(self, target_hash, prefix, charset, max_len, processed_count):
        if len(prefix) > max_len:
            return None

        hashed_guess = self.hash_string(prefix)
        if hashed_guess == target_hash:
            return prefix

        for char in charset:
            processed_count += 1
            self.app_reference.progress_bar["value"] = processed_count
            self.app_reference.root.update_idletasks()
            result = self.attempt_guess(target_hash, prefix + char, charset, max_len, processed_count)
            if result:
                return result

        return None

def launch_application():
    """Launches the Hash Cracker app."""
    root = tk.Tk()
    app_instance = HashCrackerApp(root)
    root.mainloop()

if __name__ == '__main__':
    launch_application()


    # :D