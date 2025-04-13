import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import json
import os
from cryptography.fernet import Fernet
import keyboard
import pyperclip
from threading import Thread
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
import pyautogui  # For capturing selected text
import re  # For processing dragged text

# Try to import tkinterdnd2, if not available, provide fallback
try:
    from tkinterdnd2 import DND_FILES, DND_TEXT, TkinterDnD
    DRAG_DROP_SUPPORTED = True
except ImportError:
    # Create dummy constants and set flag for drag-drop support
    DND_FILES = "DND_FILES"
    DND_TEXT = "DND_TEXT"
    DRAG_DROP_SUPPORTED = False
    # Create a simple fallback class
    class TkinterDnD:
        @staticmethod
        def Tk(*args, **kwargs):
            return tk.Tk(*args, **kwargs)


class Commander:
    def __init__(self):
        # Initialize the application
        self.root = TkinterDnD.Tk()  # Use TkinterDnD version of Tk
        self.root.title("Commander")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        self.root.attributes('-topmost', True)  # Make window stay on top
        
        # Set app icon (would need to create an icon file)
        # self.root.iconbitmap("icon.ico")
        
        # Compact mode settings
        self.is_compact_mode = False
        self.normal_geometry = "800x600"
        self.compact_geometry = "400x60"
        
        # Set styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Arial', 10), background='#4a76a8')
        self.style.configure('TLabel', font=('Arial', 12), background='#f0f0f0')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('Command.TFrame', background='#e6e6e6')
        
        # Data
        self.projects = {}  # Structure: {"Project Name": {"Tasks": {"Task Name": [commands]}}}
        self.current_project = None
        self.current_task = None
        self.accounts = {}
        self.data_file = "commander_data.enc"
        self.key = None
        self.salt = b'commander_salt_value_123'  # Fixed salt for simplicity
        self.last_captured_text = ""  # Track last captured text
        
        # Encryption setup
        self.setup_encryption()
        
        # Create compact mode bar (hidden by default)
        self.setup_compact_mode()
        
        # Create the tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Commands tab
        self.commands_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.commands_frame, text="Projects & Commands")
        self.setup_commands_tab()
        
        # Accounts tab
        self.accounts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.accounts_frame, text="Accounts")
        self.setup_accounts_tab()
        
        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()
        
        # Load data
        self.load_data()
        
        # Setup drag and drop
        self.setup_drag_drop()
        
        # Start the hotkey listener in a separate thread
        self.hotkey_thread = Thread(target=self.start_hotkey_listener, daemon=True)
        self.hotkey_thread.start()
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready | Press Ctrl+Alt+C to capture text", 
                                   bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_encryption(self):
        """Set up encryption with a password"""
        if not os.path.exists(self.data_file):
            # First time setup
            password = simpledialog.askstring("Setup", "Create a password for encryption:", 
                                              show='*')
            if not password:
                messagebox.showerror("Error", "Password is required!")
                self.root.destroy()
                return
                
            self.set_encryption_key(password)
        else:
            # Ask for existing password
            password = simpledialog.askstring("Login", "Enter your password:", show='*')
            if not password:
                messagebox.showerror("Error", "Password is required!")
                self.root.destroy()
                return
                
            self.set_encryption_key(password)
            
            # Test if password is correct by trying to load data
            try:
                with open(self.data_file, 'rb') as file:
                    encrypted_data = file.read()
                    if encrypted_data:  # Only try to decrypt if there's data
                        self.fernet.decrypt(encrypted_data)
            except Exception:
                messagebox.showerror("Error", "Invalid password!")
                self.root.destroy()
                return
    
    def set_encryption_key(self, password):
        """Generate encryption key from password"""
        password = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(self.key)
    
    def setup_commands_tab(self):
        """Set up the commands tab UI with projects and tasks structure"""
        commands_container = ttk.Frame(self.commands_frame)
        commands_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Project/Task selection
        left_frame = ttk.Frame(commands_container)
        left_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 5))
        
        # Projects section
        projects_frame = ttk.LabelFrame(left_frame, text="Projects")
        projects_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Projects listbox with scrollbar
        projects_scroll = ttk.Scrollbar(projects_frame)
        projects_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.projects_listbox = tk.Listbox(projects_frame, yscrollcommand=projects_scroll.set,
                                          font=("Arial", 11), bg="#ffffff",
                                          selectbackground="#4a76a8", height=6)
        self.projects_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        projects_scroll.config(command=self.projects_listbox.yview)
        
        # Project buttons
        project_buttons = ttk.Frame(projects_frame)
        project_buttons.pack(fill=tk.X, padx=5, pady=5)
        
        self.add_project_btn = ttk.Button(project_buttons, text="Add Project",
                                        command=self.add_project)
        self.add_project_btn.pack(side=tk.LEFT, padx=2)
        
        self.remove_project_btn = ttk.Button(project_buttons, text="Remove",
                                           command=self.remove_project)
        self.remove_project_btn.pack(side=tk.LEFT, padx=2)
        
        # Tasks section
        tasks_frame = ttk.LabelFrame(left_frame, text="Tasks")
        tasks_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tasks listbox with scrollbar
        tasks_scroll = ttk.Scrollbar(tasks_frame)
        tasks_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tasks_listbox = tk.Listbox(tasks_frame, yscrollcommand=tasks_scroll.set,
                                      font=("Arial", 11), bg="#ffffff",
                                      selectbackground="#4a76a8", height=6)
        self.tasks_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tasks_scroll.config(command=self.tasks_listbox.yview)
        
        # Task buttons
        task_buttons = ttk.Frame(tasks_frame)
        task_buttons.pack(fill=tk.X, padx=5, pady=5)
        
        self.add_task_btn = ttk.Button(task_buttons, text="Add Task",
                                     command=self.add_task)
        self.add_task_btn.pack(side=tk.LEFT, padx=2)
        
        self.remove_task_btn = ttk.Button(task_buttons, text="Remove",
                                        command=self.remove_task)
        self.remove_task_btn.pack(side=tk.LEFT, padx=2)
        
        # Right panel - Commands
        right_frame = ttk.Frame(commands_container)
        right_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(5, 0))
        
        # Commands section
        commands_frame = ttk.LabelFrame(right_frame, text="Commands")
        commands_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Commands listbox with scrollbar
        commands_scroll = ttk.Scrollbar(commands_frame)
        commands_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.commands_listbox = tk.Listbox(commands_frame, yscrollcommand=commands_scroll.set,
                                          font=("Arial", 11), bg="#ffffff",
                                          selectbackground="#4a76a8")
        self.commands_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        commands_scroll.config(command=self.commands_listbox.yview)
        
        # Command buttons
        cmd_buttons = ttk.Frame(commands_frame)
        cmd_buttons.pack(fill=tk.X, padx=5, pady=5)
        
        self.copy_btn = ttk.Button(cmd_buttons, text="Copy to Clipboard",
                                 command=self.copy_command)
        self.copy_btn.pack(side=tk.LEFT, padx=2)
        
        self.remove_cmd_btn = ttk.Button(cmd_buttons, text="Remove",
                                       command=self.remove_command)
        self.remove_cmd_btn.pack(side=tk.LEFT, padx=2)
        
        # Command details
        details_frame = ttk.LabelFrame(right_frame, text="Command Details")
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Command text area
        self.command_text = tk.Text(details_frame, wrap=tk.WORD, font=("Arial", 11),
                                  height=5, bg="#ffffff")
        self.command_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add command panel
        add_cmd_frame = ttk.Frame(details_frame)
        add_cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.add_cmd_btn = ttk.Button(add_cmd_frame, text="Add Command",
                                    command=self.add_command)
        self.add_cmd_btn.pack(side=tk.RIGHT)
        
        # Bind selection events
        self.projects_listbox.bind('<<ListboxSelect>>', self.on_project_select)
        self.tasks_listbox.bind('<<ListboxSelect>>', self.on_task_select)
        self.commands_listbox.bind('<<ListboxSelect>>', self.on_command_select)
    
    def setup_accounts_tab(self):
        """Set up the accounts tab UI"""
        accounts_container = ttk.Frame(self.accounts_frame)
        accounts_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Accounts list
        list_frame = ttk.Frame(accounts_container)
        list_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        list_label = ttk.Label(list_frame, text="Accounts")
        list_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Scrollbar and listbox
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.accounts_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, 
                                          font=("Arial", 11), bg="#ffffff",
                                          selectbackground="#4a76a8")
        self.accounts_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.accounts_listbox.yview)
        
        # Account details
        details_frame = ttk.Frame(accounts_container)
        details_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(10, 0))
        
        details_label = ttk.Label(details_frame, text="Account Details")
        details_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Form fields
        form_frame = ttk.Frame(details_frame)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Account Name
        ttk.Label(form_frame, text="Account Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.account_name_var = tk.StringVar()
        self.account_name_entry = ttk.Entry(form_frame, textvariable=self.account_name_var, width=30)
        self.account_name_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=30)
        self.username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form_frame, textvariable=self.password_var, width=30, show="•")
        self.password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.notes_text = tk.Text(form_frame, height=5, width=30, wrap=tk.WORD)
        self.notes_text.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(details_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.save_account_button = ttk.Button(button_frame, text="Save Account", 
                                             command=self.save_account)
        self.save_account_button.pack(side=tk.LEFT, padx=5)
        
        self.delete_account_button = ttk.Button(button_frame, text="Delete Account", 
                                              command=self.delete_account)
        self.delete_account_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_form_button = ttk.Button(button_frame, text="Clear Form", 
                                          command=self.clear_account_form)
        self.clear_form_button.pack(side=tk.LEFT, padx=5)
        
        # Bind select event
        self.accounts_listbox.bind('<<ListboxSelect>>', self.on_account_select)
    
    def setup_settings_tab(self):
        """Set up the settings tab UI"""
        settings_container = ttk.Frame(self.settings_frame)
        settings_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Display settings
        display_frame = ttk.LabelFrame(settings_container, text="Display Options")
        display_frame.pack(fill=tk.X, pady=10, padx=5)
        
        # Always on top option
        self.always_on_top_var = tk.BooleanVar(value=True)
        always_on_top_cb = ttk.Checkbutton(display_frame, text="Always on top", 
                                         variable=self.always_on_top_var,
                                         command=self.toggle_always_on_top)
        always_on_top_cb.pack(anchor=tk.W, pady=5, padx=10)
        
        # Compact mode option
        compact_mode_btn = ttk.Button(display_frame, text="Toggle Compact Mode", 
                                     command=self.toggle_compact_mode)
        compact_mode_btn.pack(anchor=tk.W, pady=5, padx=10)
        
        # Password settings
        password_frame = ttk.LabelFrame(settings_container, text="Security")
        password_frame.pack(fill=tk.X, pady=10, padx=5)
        
        change_pwd_button = ttk.Button(password_frame, text="Change Password", 
                                      command=self.change_password)
        change_pwd_button.pack(pady=10, padx=10)
        
        # Hotkey settings
        hotkey_frame = ttk.LabelFrame(settings_container, text="Hotkeys")
        hotkey_frame.pack(fill=tk.X, pady=10, padx=5)
        
        hotkey_info = ttk.Label(hotkey_frame, text="Press Ctrl+Alt+C to capture selected text")
        hotkey_info.pack(pady=10, padx=10)
        
        # Add manual capture button
        manual_capture = ttk.Button(hotkey_frame, text="Capture Selected Text Now", 
                                  command=self.capture_selected_text)
        manual_capture.pack(pady=5, padx=10)
        
        # Add clipboard capture button
        clipboard_capture = ttk.Button(hotkey_frame, text="Capture from Clipboard", 
                                    command=self.capture_from_clipboard)
        clipboard_capture.pack(pady=5, padx=10)
        
        # About section
        about_frame = ttk.LabelFrame(settings_container, text="About")
        about_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)
        
        about_text = """Commander

A utility tool for saving commands and secure account information.
- Press Ctrl+Alt+C to capture selected text
- Drag & drop text to add commands
- Toggle compact mode to keep it unobtrusive

Version 2.0"""
        
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT)
        about_label.pack(pady=10, padx=10)
    
    def start_hotkey_listener(self):
        """Start the global hotkey listener"""
        keyboard.add_hotkey('ctrl+alt+c', self.handle_hotkey)
        keyboard.wait()
    
    def capture_selected_text(self):
        """Capture currently selected text using keyboard shortcuts"""
        if not self.current_project or not self.current_task:
            messagebox.showinfo("Info", "Please select a project and task first")
            return None
            
        # Store current clipboard content
        original_clipboard = pyperclip.paste()
        
        # Clear clipboard
        pyperclip.copy('')
        
        # Send copy command to copy selected text
        pyautogui.hotkey('ctrl', 'c')
        # Short delay to ensure clipboard is updated
        time.sleep(0.1)
        
        # Get the selected text from clipboard
        selected_text = pyperclip.paste()
        
        if selected_text:
            # Save the selected text to current task
            task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
            task_commands.append(selected_text)
            self.update_commands_listbox()
            self.save_data()
            
            # Update status indicators
            status_message = f"Command captured: {selected_text[:20]}..."
            self.status_bar.config(text=status_message)
            if self.is_compact_mode:
                self.compact_status.config(text=status_message)
                self.root.after(3000, lambda: self.compact_status.config(text="Ready"))
            
            # Schedule status bar reset after 3 seconds
            self.root.after(3000, lambda: self.status_bar.config(
                text="Ready | Press Ctrl+Alt+C to capture text"))
            
            # Show a notification popup that auto-closes
            self.show_notification("Text Captured", 
                                  f"Added to {self.current_project} > {self.current_task}")
            
            # Store as last captured text
            self.last_captured_text = selected_text
            
            # Restore original clipboard content (optional)
            if original_clipboard:
                self.root.after(100, lambda: pyperclip.copy(original_clipboard))
            
            return selected_text
        else:
            # Try fallback to clipboard if nothing selected
            if original_clipboard and original_clipboard != self.last_captured_text:
                # Save clipboard content to current task
                task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
                task_commands.append(original_clipboard)
                self.update_commands_listbox()
                self.save_data()
                
                # Update status indicators
                status_message = f"Command captured: {original_clipboard[:20]}..."
                self.status_bar.config(text=status_message)
                if self.is_compact_mode:
                    self.compact_status.config(text=status_message)
                    self.root.after(3000, lambda: self.compact_status.config(text="Ready"))
                
                # Schedule status bar reset after 3 seconds
                self.root.after(3000, lambda: self.status_bar.config(
                    text="Ready | Press Ctrl+Alt+C to capture text"))
                
                # Show a notification popup that auto-closes
                self.show_notification("Text Captured", 
                                      f"Added to {self.current_project} > {self.current_task}")
                
                # Store as last captured text
                self.last_captured_text = original_clipboard
                
                return original_clipboard
            else:
                # Update status bar to show nothing was selected or in clipboard
                status_message = "No text selected"
                self.status_bar.config(text=status_message)
                if self.is_compact_mode:
                    self.compact_status.config(text=status_message)
                    self.root.after(3000, lambda: self.compact_status.config(text="Ready"))
                
                self.root.after(3000, lambda: self.status_bar.config(
                    text="Ready | Press Ctrl+Alt+C to capture text"))
                return None
    
    def handle_hotkey(self):
        """Handle the Ctrl+Alt+C hotkey press"""
        self.capture_selected_text()
    
    def update_commands_listbox(self):
        """Update the commands listbox"""
        self.commands_listbox.delete(0, tk.END)
        for i, cmd in enumerate(self.commands):
            # Display shortened command
            display_text = cmd[:30] + "..." if len(cmd) > 30 else cmd
            self.commands_listbox.insert(tk.END, f"{i+1}. {display_text}")
    
    def update_accounts_listbox(self):
        """Update the accounts listbox"""
        self.accounts_listbox.delete(0, tk.END)
        for account in sorted(self.accounts.keys()):
            self.accounts_listbox.insert(tk.END, account)
    
    def on_command_select(self, event):
        """Handle command selection"""
        if self.commands_listbox.curselection():
            index = self.commands_listbox.curselection()[0]
            if 0 <= index < len(self.commands):
                self.command_text.delete(1.0, tk.END)
                self.command_text.insert(tk.END, self.commands[index])
    
    def on_account_select(self, event):
        """Handle account selection"""
        if self.accounts_listbox.curselection():
            account_name = self.accounts_listbox.get(self.accounts_listbox.curselection()[0])
            account_data = self.accounts.get(account_name, {})
            
            self.account_name_var.set(account_name)
            self.username_var.set(account_data.get('username', ''))
            self.password_var.set(account_data.get('password', ''))
            
            self.notes_text.delete(1.0, tk.END)
            self.notes_text.insert(tk.END, account_data.get('notes', ''))
    
    def copy_command(self):
        """Copy selected command to clipboard"""
        if self.commands_listbox.curselection():
            index = self.commands_listbox.curselection()[0]
            if 0 <= index < len(self.commands):
                pyperclip.copy(self.commands[index])
                self.status_bar.config(text="Command copied to clipboard")
                self.root.after(3000, lambda: self.status_bar.config(
                    text="Ready | Press Ctrl+Alt+C to capture text"))
    
    def delete_command(self):
        """Delete selected command"""
        if self.commands_listbox.curselection():
            index = self.commands_listbox.curselection()[0]
            if 0 <= index < len(self.commands):
                del self.commands[index]
                self.update_commands_listbox()
                self.command_text.delete(1.0, tk.END)
                self.save_data()
    
    def add_command(self):
        """Add a new command manually"""
        new_command = self.new_command_text.get(1.0, tk.END).strip()
        if new_command:
            self.commands.append(new_command)
            self.update_commands_listbox()
            self.new_command_text.delete(1.0, tk.END)
            self.save_data()
    
    def save_account(self):
        """Save account information"""
        account_name = self.account_name_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        notes = self.notes_text.get(1.0, tk.END).strip()
        
        if not account_name:
            messagebox.showwarning("Input Error", "Account name is required!")
            return
        
        self.accounts[account_name] = {
            'username': username,
            'password': password,
            'notes': notes
        }
        
        self.update_accounts_listbox()
        self.save_data()
        messagebox.showinfo("Success", "Account information saved!")
    
    def delete_account(self):
        """Delete selected account"""
        if self.accounts_listbox.curselection():
            account_name = self.accounts_listbox.get(self.accounts_listbox.curselection()[0])
            if messagebox.askyesno("Confirm Delete", f"Delete account '{account_name}'?"):
                del self.accounts[account_name]
                self.update_accounts_listbox()
                self.clear_account_form()
                self.save_data()
    
    def clear_account_form(self):
        """Clear the account form"""
        self.account_name_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        self.notes_text.delete(1.0, tk.END)
    
    def change_password(self):
        """Change encryption password"""
        old_password = simpledialog.askstring("Password", "Enter current password:", show='*')
        if not old_password:
            return
        
        # Verify old password
        try:
            test_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            test_key = base64.urlsafe_b64encode(test_kdf.derive(old_password.encode()))
            test_fernet = Fernet(test_key)
            
            # Try to decrypt data
            with open(self.data_file, 'rb') as file:
                encrypted_data = file.read()
                if encrypted_data:  # Only try to decrypt if there's data
                    test_fernet.decrypt(encrypted_data)
        except Exception:
            messagebox.showerror("Error", "Invalid current password!")
            return
        
        # Get new password
        new_password = simpledialog.askstring("Password", "Enter new password:", show='*')
        if not new_password:
            return
        
        confirm_password = simpledialog.askstring("Password", "Confirm new password:", show='*')
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        # Set new encryption key
        self.set_encryption_key(new_password)
        self.save_data()
        
        messagebox.showinfo("Success", "Password changed successfully!")
    
    def load_data(self):
        """Load encrypted data from file"""
        if not os.path.exists(self.data_file):
            return
        
        try:
            with open(self.data_file, 'rb') as file:
                encrypted_data = file.read()
                if not encrypted_data:  # Empty file
                    return
                    
                decrypted_data = self.fernet.decrypt(encrypted_data)
                data = json.loads(decrypted_data.decode())
                
                # Handle existing format to new format conversion
                if "commands" in data and data["commands"]:
                    # Convert old format to new format
                    self.projects = {"Default Project": {"Tasks": {"Default Task": data["commands"]}}}
                else:
                    self.projects = data.get('projects', {})
                
                self.accounts = data.get('accounts', {})
                
                self.update_projects_listbox()
                self.update_tasks_listbox()
                self.update_commands_listbox()
                self.update_accounts_listbox()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load data: {str(e)}")
    
    def save_data(self):
        """Save encrypted data to file"""
        try:
            data = {
                'projects': self.projects,
                'accounts': self.accounts
            }
            
            encrypted_data = self.fernet.encrypt(json.dumps(data).encode())
            
            with open(self.data_file, 'wb') as file:
                file.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")
    
    def setup_compact_mode(self):
        """Setup the compact mode bar"""
        self.compact_frame = ttk.Frame(self.root)
        self.compact_frame.pack_forget()  # Hidden by default
        
        # Project and Task selection frame
        selection_frame = ttk.Frame(self.compact_frame)
        selection_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)
        
        # Project selection
        project_frame = ttk.Frame(selection_frame)
        project_frame.pack(fill=tk.X)
        
        ttk.Label(project_frame, text="Project:").pack(side=tk.LEFT)
        self.compact_project_var = tk.StringVar()
        self.compact_project = ttk.Combobox(project_frame, textvariable=self.compact_project_var,
                                          width=15, state="readonly")
        self.compact_project.pack(side=tk.LEFT, padx=5)
        self.compact_project.bind("<<ComboboxSelected>>", self.on_compact_project_change)
        
        # Task selection
        task_frame = ttk.Frame(selection_frame)
        task_frame.pack(fill=tk.X, pady=(2, 0))
        
        ttk.Label(task_frame, text="Task:").pack(side=tk.LEFT)
        self.compact_task_var = tk.StringVar()
        self.compact_task = ttk.Combobox(task_frame, textvariable=self.compact_task_var,
                                       width=15, state="readonly")
        self.compact_task.pack(side=tk.LEFT, padx=5)
        self.compact_task.bind("<<ComboboxSelected>>", self.on_compact_task_change)
        
        # Button to expand to full mode
        expand_btn = ttk.Button(self.compact_frame, text="Expand", 
                              command=self.toggle_compact_mode)
        expand_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Quick capture button
        capture_btn = ttk.Button(self.compact_frame, text="Capture", 
                               command=self.capture_selected_text)
        capture_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Status label
        self.compact_status = ttk.Label(self.compact_frame, text="Ready")
        self.compact_status.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
    
    def on_compact_project_change(self, event):
        """Handle project selection in compact mode"""
        project = self.compact_project_var.get()
        if project and project in self.projects:
            self.current_project = project
            self.update_compact_tasks()
            # Clear task selection
            self.compact_task.set('')
            self.current_task = None

    def on_compact_task_change(self, event):
        """Handle task selection in compact mode"""
        task = self.compact_task_var.get()
        if task and self.current_project and task in self.projects[self.current_project]["Tasks"]:
            self.current_task = task

    def update_compact_projects(self):
        """Update projects dropdown in compact mode"""
        project_list = list(self.projects.keys())
        self.compact_project['values'] = project_list
        
        if self.current_project in project_list:
            self.compact_project.set(self.current_project)
        else:
            self.compact_project.set('')

    def update_compact_tasks(self):
        """Update tasks dropdown in compact mode"""
        if self.current_project and self.current_project in self.projects:
            task_list = list(self.projects[self.current_project]["Tasks"].keys())
            self.compact_task['values'] = task_list
            
            if self.current_task in task_list:
                self.compact_task.set(self.current_task)
            else:
                self.compact_task.set('')
        else:
            self.compact_task['values'] = []
            self.compact_task.set('')

    def toggle_compact_mode(self):
        """Toggle between compact and full mode"""
        if self.is_compact_mode:
            # Switch to full mode
            self.compact_frame.pack_forget()
            self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            self.root.geometry(self.normal_geometry)
            self.is_compact_mode = False
        else:
            # Switch to compact mode
            self.notebook.pack_forget()
            self.status_bar.pack_forget()
            self.compact_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
            self.root.geometry(self.compact_geometry)
            self.is_compact_mode = True
            # Update project/task selection
            self.update_compact_projects()
            self.update_compact_tasks()
    
    def setup_drag_drop(self):
        """Setup drag and drop functionality"""
        if not DRAG_DROP_SUPPORTED:
            self.status_bar.config(text="Drag & Drop not available. Install tkinterdnd2 package.")
            self.root.after(5000, lambda: self.status_bar.config(
                text="Ready | Press Ctrl+Alt+C to capture text"))
            return
            
        # Enable drag and drop for the main window
        self.root.drop_target_register(DND_TEXT)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)
        
        # Enable drag and drop for the command text area
        self.command_text.drop_target_register(DND_TEXT)
        self.command_text.dnd_bind('<<Drop>>', self.handle_text_drop)
    
    def handle_drop(self, event):
        """Handle text drop on the main window"""
        if not self.current_project or not self.current_task:
            messagebox.showinfo("Info", "Please select a project and task first")
            return
            
        data = event.data
        if data:
            # Clean dropped text (might have file path format or quotes)
            clean_text = self.clean_dropped_text(data)
            if clean_text:
                # Add to current task
                task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
                task_commands.append(clean_text)
                self.update_commands_listbox()
                self.save_data()
                
                self.compact_status.config(text="Text captured!")
                self.status_bar.config(text=f"Command captured: {clean_text[:20]}...")
                self.root.after(3000, lambda: self.status_bar.config(
                    text="Ready | Press Ctrl+Alt+C to capture text"))
                self.root.after(3000, lambda: self.compact_status.config(text="Ready"))
                
                # Show notification
                self.show_notification("Text Captured", 
                                      f"Added to {self.current_project} > {self.current_task}")
    
    def handle_text_drop(self, event):
        """Handle text drop in the command text area"""
        data = event.data
        if data:
            clean_text = self.clean_dropped_text(data)
            self.command_text.delete(1.0, tk.END)
            self.command_text.insert(tk.END, clean_text)
    
    def clean_dropped_text(self, text):
        """Clean dropped text from format artifacts"""
        # Remove curly braces and extra quotes that sometimes come with dropped text
        text = text.strip('{}"\'')
        # If it looks like a file path but the file doesn't exist, treat as text
        if text.startswith(('/', 'C:', 'D:')) and not os.path.exists(text):
            text = text.replace('\\', '/')  # Normalize slashes
        return text
    
    def toggle_always_on_top(self):
        """Toggle whether the window stays on top"""
        on_top = self.always_on_top_var.get()
        self.root.attributes('-topmost', on_top)
    
    def capture_from_clipboard(self):
        """Capture text directly from clipboard"""
        if not self.current_project or not self.current_task:
            messagebox.showinfo("Info", "Please select a project and task first")
            return None
            
        clipboard_content = pyperclip.paste()
        
        if clipboard_content and clipboard_content != self.last_captured_text:
            # Add to current task
            task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
            task_commands.append(clipboard_content)
            self.update_commands_listbox()
            self.save_data()
            
            # Update status bar
            self.status_bar.config(text=f"Command captured: {clipboard_content[:20]}...")
            self.root.after(3000, lambda: self.status_bar.config(
                text="Ready | Press Ctrl+Alt+C to capture text"))
            
            # Show notification
            self.show_notification("Text Captured", 
                                  f"Added to {self.current_project} > {self.current_task}")
            
            # Store as last captured text
            self.last_captured_text = clipboard_content
            
            return clipboard_content
        else:
            # Update status bar to show nothing was in clipboard
            self.status_bar.config(text="No new text in clipboard")
            self.root.after(3000, lambda: self.status_bar.config(
                text="Ready | Press Ctrl+Alt+C to capture text"))
            return None
    
    def show_notification(self, title, message):
        """Show a small notification popup that auto-dismisses"""
        # Create a toplevel window
        notification = tk.Toplevel(self.root)
        notification.title(title)
        notification.geometry("300x80+{}+{}".format(
            self.root.winfo_screenwidth() - 320, 
            self.root.winfo_screenheight() - 100))
        notification.attributes('-topmost', True)
        notification.overrideredirect(True)  # Remove window decorations
        
        # Add a frame with a border
        frame = tk.Frame(notification, bg="#4a76a8", bd=2)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add message
        msg_label = tk.Label(frame, text=message, bg="#f0f0f0", fg="#333333",
                          font=("Arial", 10), wraplength=280, pady=10, padx=10)
        msg_label.pack(fill=tk.BOTH, expand=True)
        
        # Auto close after 2 seconds
        notification.after(2000, notification.destroy)
    
    def run(self):
        """Run the application"""
        # Add keyboard shortcut for toggling compact mode
        keyboard.add_hotkey('ctrl+alt+m', self.toggle_compact_mode)
        
        # Create default project and task if none exist
        if not self.projects:
            self.projects["Default Project"] = {"Tasks": {"General": []}}
            self.update_projects_listbox()
            
            # Select the default project and task
            self.current_project = "Default Project"
            self.current_task = "General"
            
            if self.projects_listbox.size() > 0:
                self.projects_listbox.selection_set(0)
                self.update_tasks_listbox()
                if self.tasks_listbox.size() > 0:
                    self.tasks_listbox.selection_set(0)
        
        self.root.mainloop()

    def add_project(self):
        """Add a new project"""
        project_name = simpledialog.askstring("Add Project", "Enter project name:")
        if not project_name:
            return
            
        if project_name in self.projects:
            messagebox.showwarning("Warning", f"Project '{project_name}' already exists!")
            return
            
        self.projects[project_name] = {"Tasks": {}}
        self.update_projects_listbox()
        self.save_data()
        
        # Select the new project
        idx = list(self.projects.keys()).index(project_name)
        self.projects_listbox.selection_clear(0, tk.END)
        self.projects_listbox.selection_set(idx)
        self.projects_listbox.see(idx)
        self.on_project_select(None)
    
    def remove_project(self):
        """Remove selected project"""
        if not self.projects_listbox.curselection():
            messagebox.showinfo("Info", "No project selected")
            return
            
        idx = self.projects_listbox.curselection()[0]
        project_name = self.projects_listbox.get(idx)
        
        if messagebox.askyesno("Confirm Delete", 
                              f"Delete project '{project_name}' and all its content?"):
            del self.projects[project_name]
            self.update_projects_listbox()
            self.update_tasks_listbox()
            self.update_commands_listbox()
            self.current_project = None
            self.current_task = None
            self.save_data()
    
    def add_task(self):
        """Add a new task to the current project"""
        if not self.current_project:
            messagebox.showinfo("Info", "Please select a project first")
            return
            
        task_name = simpledialog.askstring("Add Task", "Enter task name:")
        if not task_name:
            return
            
        if task_name in self.projects[self.current_project]["Tasks"]:
            messagebox.showwarning("Warning", f"Task '{task_name}' already exists in this project!")
            return
            
        self.projects[self.current_project]["Tasks"][task_name] = []
        self.update_tasks_listbox()
        self.save_data()
        
        # Select the new task
        idx = list(self.projects[self.current_project]["Tasks"].keys()).index(task_name)
        self.tasks_listbox.selection_clear(0, tk.END)
        self.tasks_listbox.selection_set(idx)
        self.tasks_listbox.see(idx)
        self.on_task_select(None)
    
    def remove_task(self):
        """Remove selected task"""
        if not self.current_project:
            messagebox.showinfo("Info", "Please select a project first")
            return
            
        if not self.tasks_listbox.curselection():
            messagebox.showinfo("Info", "No task selected")
            return
            
        idx = self.tasks_listbox.curselection()[0]
        task_name = self.tasks_listbox.get(idx)
        
        if messagebox.askyesno("Confirm Delete", f"Delete task '{task_name}' and all its commands?"):
            del self.projects[self.current_project]["Tasks"][task_name]
            self.update_tasks_listbox()
            self.update_commands_listbox()
            self.current_task = None
            self.save_data()
    
    def add_command(self):
        """Add a new command to the current task"""
        if not self.current_project or not self.current_task:
            messagebox.showinfo("Info", "Please select a project and task first")
            return
            
        command_text = self.command_text.get(1.0, tk.END).strip()
        if not command_text:
            messagebox.showinfo("Info", "Please enter a command")
            return
            
        task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
        task_commands.append(command_text)
        self.update_commands_listbox()
        self.command_text.delete(1.0, tk.END)
        self.save_data()
    
    def remove_command(self):
        """Remove selected command"""
        if not self.current_project or not self.current_task:
            return
            
        if not self.commands_listbox.curselection():
            messagebox.showinfo("Info", "No command selected")
            return
            
        idx = self.commands_listbox.curselection()[0]
        task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
        
        if 0 <= idx < len(task_commands):
            del task_commands[idx]
            self.update_commands_listbox()
            self.command_text.delete(1.0, tk.END)
            self.save_data()
    
    def on_project_select(self, event):
        """Handle project selection"""
        if not self.projects_listbox.curselection():
            return
            
        idx = self.projects_listbox.curselection()[0]
        project_name = self.projects_listbox.get(idx)
        self.current_project = project_name
        self.current_task = None
        
        self.update_tasks_listbox()
        self.update_commands_listbox()
    
    def on_task_select(self, event):
        """Handle task selection"""
        if not self.current_project or not self.tasks_listbox.curselection():
            return
            
        idx = self.tasks_listbox.curselection()[0]
        task_name = self.tasks_listbox.get(idx)
        self.current_task = task_name
        
        self.update_commands_listbox()
    
    def on_command_select(self, event):
        """Handle command selection"""
        if not self.current_project or not self.current_task:
            return
            
        if not self.commands_listbox.curselection():
            return
            
        idx = self.commands_listbox.curselection()[0]
        task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
        
        if 0 <= idx < len(task_commands):
            self.command_text.delete(1.0, tk.END)
            self.command_text.insert(tk.END, task_commands[idx])
    
    def update_projects_listbox(self):
        """Update the projects listbox"""
        self.projects_listbox.delete(0, tk.END)
        for project in self.projects:
            self.projects_listbox.insert(tk.END, project)
    
    def update_tasks_listbox(self):
        """Update the tasks listbox based on selected project"""
        self.tasks_listbox.delete(0, tk.END)
        
        if not self.current_project:
            return
            
        if self.current_project in self.projects:
            for task in self.projects[self.current_project]["Tasks"]:
                self.tasks_listbox.insert(tk.END, task)
    
    def update_commands_listbox(self):
        """Update the commands listbox based on selected task"""
        self.commands_listbox.delete(0, tk.END)
        
        if not self.current_project or not self.current_task:
            return
            
        if (self.current_project in self.projects and 
            self.current_task in self.projects[self.current_project]["Tasks"]):
            commands = self.projects[self.current_project]["Tasks"][self.current_task]
            for i, cmd in enumerate(commands):
                display_text = cmd[:30] + "..." if len(cmd) > 30 else cmd
                self.commands_listbox.insert(tk.END, f"{i+1}. {display_text}")
    
    def copy_command(self):
        """Copy selected command to clipboard"""
        if not self.current_project or not self.current_task:
            return
            
        if not self.commands_listbox.curselection():
            return
            
        idx = self.commands_listbox.curselection()[0]
        task_commands = self.projects[self.current_project]["Tasks"][self.current_task]
        
        if 0 <= idx < len(task_commands):
            pyperclip.copy(task_commands[idx])
            self.status_bar.config(text="Command copied to clipboard")
            self.root.after(3000, lambda: self.status_bar.config(
                text="Ready | Press Ctrl+Alt+C to capture text"))


def check_dependencies():
    """Check if all required dependencies are installed"""
    missing = []
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        missing.append("tkinter")
    
    try:
        import cryptography
    except ImportError:
        missing.append("cryptography")
    
    try:
        import keyboard
    except ImportError:
        missing.append("keyboard")
    
    try:
        import pyperclip
    except ImportError:
        missing.append("pyperclip")
    
    try:
        import pyautogui
    except ImportError:
        missing.append("pyautogui")
    
    try:
        from tkinterdnd2 import DND_FILES
    except ImportError:
        missing.append("tkinterdnd2")
    
    if missing:
        print("Missing dependencies: " + ", ".join(missing))
        print("Please install them using: pip install " + " ".join(missing))
        print("Or run: pip install -r requirements.txt")
        input("Press Enter to exit...")
        return False
    return True


if __name__ == "__main__":
    if check_dependencies():
        app = Commander()
        app.run()