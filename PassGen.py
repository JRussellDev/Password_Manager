
import secrets # for password generation
import string # For split functions
import os #FOR Debugging and error checking
import tkinter as tk #GUI 
from cryptography.fernet import Fernet # For encryption/decryption

# Function to switch frames
def show_frame(frame):
    frame.tkraise()


# Load the key (must be the same key used for encryption)
def LoadKey():
    with open('secret.key', 'rb') as key_file:
        key = key_file.read()

    return key


# Function to generate ID
def generate_short_id(length):
    characters = string.ascii_letters + string.digits  # Use letters and digits
    short_id = ''.join(secrets.choice(characters) for _ in range(length))
    return short_id

# Encrypt data
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data.encode())

# Decrypt data
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_data).decode()




def SaveGeneratedPassword(key, passLocation, genPass):
      #generate random password with secrets library
        alphabet = string.ascii_letters + string.digits + string.punctuation #Using all types of characters
        password_length = 12
        newPassword = ''.join(secrets.choice(alphabet) for _ in range(password_length))  #Choose random character for length of password
        
        encrypted_password = encrypt_data(newPassword, key)     #Encrypt password
        password_id = generate_short_id(8) # Generate unique id
        
        genPass.config(text = newPassword) #Set generated password label to the new password
        
        # Save to file
        with open("passwordfile.txt", 'a') as file:
            file.write(f"{password_id}:{passLocation}:{encrypted_password.decode()}\n")
        
        frames["SavePassword"].self.userPassTypeInp.config(text="") #Clear entry box to indicate proccess


def SaveNewPassword(key, passLocation, newPassword): #Save a new password
    
    # Show the correct UI frame
    show_frame(frames["SavePassword"]) 
 
    encrypted_password = encrypt_data(newPassword, key)
    password_id = secrets.short_id(length=5) # Generate unique id

    # Save to file
    with open("passwordfile.txt", 'a') as file:
        file.write(f"{password_id}:{passLocation}:{encrypted_password.decode()}\n")     #Save new line combining required variables
    
    frames["SavePassword"].self.userPassTypeInp.config(text="")  # Clear entry box
    frames["SavePassword"].self.userPassInp.config(text="")  # Clear entry box
    

def RemovePassword(key, id):
    
    with open("passwordfile.txt", 'r') as file:  # Read files and save into a list
        lines = file.readlines()
    
    with open("passwordfile.txt", 'w') as file:   # Write files to filter out line to remove
    
        print("Saved passwords:")
        for line in lines: # For each line in file, decrypt and print
            password_id, passLocation, encrypted_password = line.strip().split(":", 2) #Split data into the correct variables
            if password_id != id:   #Only write line if it doesnt = the id to remove
                file.write(line)
            else:
                print(f"Password for {passLocation} has been removed.\n")
    frames["ListPasswords"].removeEntry.config(text="")
    ListAllPasswords(key)
    
   
   
def ListAllPasswords(key):
    
    # Show the correct UI frame
    show_frame(frames["ListPasswords"]) 
    
    if not os.path.exists("passwordfile.txt"): #Check file is not empty
        print("No passwords saved.")
        return

    # Clear existing labels
    for widget in frames["ListPasswords"].scrollable_frame.winfo_children():
        widget.destroy()

    with open("passwordfile.txt", 'r') as file:
        lines = file.readlines()                   #Get data from file and save to lines variable
    
    x = 1

    for x, line in enumerate(lines, start=1):  # For each line in file, decrypt and print (also loop and increment through x for row)
        line = line.strip() # Remove any weird extra spaces
        if not line: # Skip empty lines
            continue  
        try:
            password_id, pass_location, encrypted_password = line.split(":", 2)  # Split data into the correct variables
            decrypted_password = decrypt_data(encrypted_password.encode(), key)

            lineLabel = tk.Label(frames["ListPasswords"].scrollable_frame, text=(f"{password_id} : {pass_location} : {decrypted_password}")) # Create a new label for each line in file
            lineLabel.grid(row=x, column=0, sticky="w")        
            x+=1
            
        except ValueError as e:               # Error exception
            print(f"Error processing line: {line}, error: {e}")
             

def SearchSpecificPassword(key, search):
     
    with open("passwordfile.txt", 'r') as file:
        lines = file.readlines()
    
    for line in lines:
        password_id, passLocation, encrypted_password = line.strip().split(":", 2)     
        decrypted_password = decrypt_data(encrypted_password.encode(), key)
        if (passLocation == search):        # Check if account type of line equals the search
            {
            frames["ListPasswords"].searchResultLbl.config(text=(f"The password for {passLocation} is: {decrypted_password}"))   # Display correct search
            }
    frames["ListPasswords"].searchEntry.config(text="")








#UI CLASSES
    
class ListPasswords(tk.Frame):

    def __init__(self, parent, controller, key):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.key = key

        ScreenTitleLbl = tk.Label(self, text="Password List")
        ScreenTitleLbl.grid(row=0, column=1)
       
        SaveNewPassBtn = tk.Button(self, command=lambda: show_frame(frames["SavePassword"]), text="Save New Password")
        SaveNewPassBtn.grid(row=0, column=0)
        
        listFormatLbl = tk.Label(self, text="Format = PasswordID : Account Type : Password")
        listFormatLbl.grid(row=0, column=2, sticky="w")

        refreshBtn = tk.Button(self, text="Re-list", command=lambda: ListAllPasswords(key))
        refreshBtn.grid(row=0,column=3)
        
        # Creating a canvas and scrollbar
        self.canvas = tk.Canvas(self)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
        "<Configure>",
        lambda e: self.canvas.configure(
        scrollregion=self.canvas.bbox("all")
        )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.grid(row=2, column=0, columnspan=3, sticky="nsew")
        self.scrollbar.grid(row=2, column=3, sticky="ns")
        
        #Search Password UI
        searchLbl = tk.Label(self, text="Enter account to search: ")
        searchLbl.grid(row=3, column=0,sticky="e")
        
        self.searchEntry = tk.Entry(self, width=50)
        self.searchEntry.grid(row=3, column=1, sticky="w")
        
        searchResultTextLbl = tk.Label(self, text="Result: ")
        searchResultTextLbl.grid(row=4, column=0)
        
        self.searchResultLbl = tk.Label(self)
        self.searchResultLbl.grid(row=4, column=1)

        searchBtn = tk.Button(self, text="Search", command=lambda: SearchSpecificPassword(key, self.searchEntry.get()))
        searchBtn.grid(row=3, column=2, sticky="w")
       
        #Remove Password UI
        removeLbl = tk.Label(self, text="Enter ID of line to remove: ")
        removeLbl.grid(row=5, column=0, sticky="e")
        
        self.removeEntry = tk.Entry(self, width=50)
        self.removeEntry.grid(row=5, column=1, sticky="w")
        
        removeBtn = tk.Button(self, text="Remove", command=lambda: RemovePassword(key, self.removeEntry.get())) 
        removeBtn.grid(row=5, column=2, sticky="w")
        
        
        
    
    
class SavePassword(tk.Frame):

    def __init__(self, parent, controller, key):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.key = key
        
        backBtn = tk.Button(self, command=lambda: show_frame(frames["ListPasswords"]), text="Main Menu")
        backBtn.grid(row=0, column=0) 
        
        screenTitleLbl = tk.Label(self, text="Save New Password")
        screenTitleLbl.grid(row=0, column=1)   
        
        # Account Of Password
        passLocationLbl = tk.Label(self, text="Enter Account Of Password To Save (eg Disney+, Amazon):")
        passLocationLbl.grid(row=1, column=0)
        
        self.userPassTypeInp = tk.Entry(self, width=50)
        self.userPassTypeInp.grid(row=1, column=1)
        
        
        #GENERATED PASSWORD
        genPassLbl = tk.Label(self, text="Generate Secure Password")
        genPassLbl.grid(row=2, column=0)
        
        genPassBtn = tk.Button(self, text="Generate And Save", command=lambda: SaveGeneratedPassword(key, self.userPassTypeInp.get(), displayGenPass) )
        genPassBtn.grid(row=2, column=1)
        
        genPass = tk.Label(self, text="Generated Password: ")
        genPass.grid(row=3, column=0)
        
        displayGenPass = tk.Label(self)
        displayGenPass.grid(row=3, column=1)
        
        #USER INPUT PASSWORD
        userPassLbl = tk.Label(self, text="Enter Own Password To Save:")
        userPassLbl.grid(row=6, column=0)
        
        self.userPassInp = tk.Entry(self, width=50)
        self.userPassInp.grid(row=6, column=1)
        
        userPassBtn = tk.Button(self, command=lambda: SaveNewPassword(key, self.userPassTypeInp.get(), self.userPassInp.get()), text="Save")
        userPassBtn.grid(row=7, column=1)
        
        
          
        
        
# Create Root
root = tk.Tk() 
root.title("Jamie's Password Manager") # Set title

# Function to switch frames
def show_frame(frame):
    frame.tkraise()

# Create container frame
container = tk.Frame(root)
container.pack(side="top", fill="both", expand=True)

key = LoadKey() # Load encryption key

# Create a dictionary to hold the different frames
frames = {}

# Define frames for Main Menu and List Passwords
for F in (ListPasswords, SavePassword):
        page_name = F.__name__
        frame = F(parent=container, controller=root, key=key)
        frames[page_name] = frame
        frame.grid(row=0, column=0, sticky="nsew")
    
    
# Initialize the main frame
ListAllPasswords(key) # List all passwords on program start


      
if __name__ == "__main__":  # Check if file is being run directly
    
    root.mainloop()   # Start UI main loop

