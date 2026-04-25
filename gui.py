import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
import os
import json
import ipaddress
from datetime import datetime
from pathlib import Path

from main import IoTVulnerabilityScanner
from utils.database import ScannerDB

class IoTScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Security Guard - Professional Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(900, 700)

        self.db = ScannerDB()
        self.current_user_id = None
        self.current_username = None
        self.current_user_role = None
        
        self.scanner = None
        self.scan_thread = None
        self.last_results = None
        self.stop_event = threading.Event()
        
        # Theme state
        self.is_dark_theme = True
        self.theme_colors = self._get_dark_theme()
        
        self.style = ttk.Style()
        self._setup_styles()
        self._show_login_page()

    def _get_dark_theme(self):
        """Returns dark theme colors"""
        return {
            'bg': '#0f172a',
            'bg_secondary': '#1e293b',
            'bg_tertiary': '#334155',
            'fg': '#cbd5e1',
            'fg_secondary': '#94a3b8',
            'accent': '#00d4ff',
            'accent_hover': '#06b6d4',
            'success': '#10b981',
            'warning': '#f97316',
            'error': '#ef4444',
            'card_bg': '#1e293b',
            'card_border': '#334155'
        }

    def _get_light_theme(self):
        """Returns light theme colors"""
        return {
            'bg': '#f8fafc',
            'bg_secondary': '#ffffff',
            'bg_tertiary': '#e2e8f0',
            'fg': '#1e293b',
            'fg_secondary': '#64748b',
            'accent': '#3b82f6',
            'accent_hover': '#2563eb',
            'success': '#10b981',
            'warning': '#f97316',
            'error': '#ef4444',
            'card_bg': '#ffffff',
            'card_border': '#e2e8f0'
        }

    def _setup_styles(self):
        """Configure all TTK styles based on current theme"""
        colors = self.theme_colors
        
        self.root.configure(bg=colors['bg'])
        self.style.theme_use('clam')
        
        # Frame styles
        self.style.configure('TFrame', background=colors['bg'])
        self.style.configure('Card.TFrame', background=colors['card_bg'], relief='flat', borderwidth=0)
        self.style.configure('Sidebar.TFrame', background=colors['bg'])
        
        # Label styles
        self.style.configure('TLabel', background=colors['bg'], font=('Segoe UI', 10), foreground=colors['fg'])
        self.style.configure('Header.TLabel', font=('Segoe UI', 24, 'bold'), foreground=colors['fg'], background=colors['bg'])
        self.style.configure('SubHeader.TLabel', font=('Segoe UI', 14, 'bold'), foreground=colors['fg'], background=colors['bg'])
        self.style.configure('Section.TLabel', font=('Segoe UI', 11, 'bold'), foreground=colors['fg_secondary'], background=colors['card_bg'])
        
        # Button styles
        self.style.configure('TButton', font=('Segoe UI', 10), relief='flat', borderwidth=0)
        
        self.style.configure('Action.TButton', font=('Segoe UI', 11, 'bold'), padding=(16, 8),
                            background=colors['accent'], foreground='#0f172a')
        self.style.map('Action.TButton', background=[('active', colors['accent_hover'])])
        
        self.style.configure('Secondary.TButton', font=('Segoe UI', 10), padding=(12, 6),
                            background=colors['bg_tertiary'], foreground=colors['fg'])
        self.style.map('Secondary.TButton', background=[('active', colors['bg_secondary'])])
        
        # Entry styles
        self.style.configure('TEntry', font=('Segoe UI', 11), fieldbackground=colors['bg_secondary'],
                            foreground=colors['fg'], borderwidth=1, relief='solid')
        
        # Treeview styles
        self.style.configure('Treeview', font=('Segoe UI', 10), rowheight=28,
                            background=colors['card_bg'], fieldbackground=colors['card_bg'],
                            foreground=colors['fg'], borderwidth=0, relief='flat')
        self.style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'),
                            background=colors['bg_secondary'], foreground=colors['fg_secondary'],
                            relief='flat', borderwidth=0, padding=(8, 5))
        self.style.map('Treeview.Heading', background=[('active', colors['bg_tertiary'])])
        self.style.map('Treeview', background=[('selected', colors['accent'])],
                      foreground=[('selected', '#0f172a')])

    def _toggle_theme(self):
        """Toggle between dark and light themes"""
        self.is_dark_theme = not self.is_dark_theme
        self.theme_colors = self._get_dark_theme() if self.is_dark_theme else self._get_light_theme()
        self._setup_styles()
        # Refresh current view
        if hasattr(self, 'current_view'):
            self.current_view()

    def _clear_root(self):
        """Clear all widgets from root"""
        for widget in self.root.winfo_children():
            widget.destroy()

    # ===== AUTHENTICATION PAGES =====

    def _show_login_page(self):
        """Professional split-screen login interface"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        self.current_view = self._show_login_page
        
        main_frame = tk.Frame(self.root, bg=colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left Panel - Branding
        left_panel = tk.Frame(main_frame, bg=colors['bg'], width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        left_panel.pack_propagate(False)
        
        branding_frame = tk.Frame(left_panel, bg=colors['bg'])
        branding_frame.pack(pady=(80, 50), padx=40, expand=True)
        
        tk.Label(branding_frame, text="🛡️", font=('Segoe UI', 72), 
                bg=colors['bg'], fg=colors['accent']).pack()
        tk.Label(branding_frame, text="IoT Guard", 
                font=('Segoe UI', 28, 'bold'), bg=colors['bg'], fg=colors['accent']).pack(pady=(15, 5))
        tk.Label(branding_frame, text="Advanced Network Security", 
                font=('Segoe UI', 12), bg=colors['bg'], fg=colors['fg_secondary']).pack()
        
        features = tk.Frame(branding_frame, bg=colors['bg'])
        features.pack(pady=(40, 0), fill=tk.X)
        
        for feature in ["✓ Real-time Scanning", "✓ Multi-device Support", "✓ Advanced Reporting"]:
            tk.Label(features, text=feature, font=('Segoe UI', 11), 
                    bg=colors['bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=3)
        
        # Right Panel - Login Form
        right_panel = tk.Frame(main_frame, bg=colors['bg'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=50, pady=60)
        
        login_card = tk.Frame(right_panel, bg=colors['card_bg'], padx=40, pady=40,
                            highlightthickness=1, highlightbackground=colors['card_border'])
        login_card.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(login_card, text="Sign In", font=('Segoe UI', 26, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(pady=(0, 30))
        
        # Username
        tk.Label(login_card, text="Username or Email", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        user_entry = ttk.Entry(login_card, width=40)
        user_entry.pack(fill=tk.X, ipady=8, pady=(0, 20))
        
       # Password
        tk.Label(login_card, text="Password", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        
        # Frame to hold the entry and toggle button side-by-side
        pass_frame = tk.Frame(login_card, bg=colors['card_bg'])
        pass_frame.pack(fill=tk.X, pady=(0, 20))
        
        pass_entry = ttk.Entry(pass_frame, show="•")
        pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        
        # Function to toggle the visibility and icon
        def toggle_password():
            if pass_entry.cget('show') == '•':
                pass_entry.config(show='')
                toggle_btn.config(text='🙈')
            else:
                pass_entry.config(show='•')
                toggle_btn.config(text='👁️')
                
        # The visibility toggle button styled to match theme
        toggle_btn = tk.Button(pass_frame, text="👁️", font=('Segoe UI', 11), 
                              bg=colors['bg_tertiary'], fg=colors['fg'], 
                              relief='flat', cursor="hand2", command=toggle_password,
                              activebackground=colors['bg_secondary'])
        toggle_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=5)
        
        # Remember and links
        options_frame = tk.Frame(login_card, bg=colors['card_bg'])
        options_frame.pack(fill=tk.X, pady=(0, 25))
        
        remember_var = tk.BooleanVar()
        tk.Checkbutton(options_frame, text="Remember me", variable=remember_var,
                      bg=colors['card_bg'], fg=colors['fg'], selectcolor=colors['accent'],
                      activebackground=colors['card_bg'], font=('Segoe UI', 10)).pack(side=tk.LEFT)
        
        links = tk.Frame(options_frame, bg=colors['card_bg'])
        links.pack(side=tk.RIGHT)
        
        tk.Button(links, text="Sign Up", bg=colors['card_bg'], fg=colors['accent'],
                 relief='flat', font=('Segoe UI', 10, 'bold'), cursor="hand2",
                 command=self._show_signup_page, activebackground=colors['card_bg']).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Button(links, text="Forgot Password?", bg=colors['card_bg'], fg=colors['accent'],
                 relief='flat', font=('Segoe UI', 10, 'bold'), cursor="hand2",
                 command=self._show_forgot_password, activebackground=colors['card_bg']).pack(side=tk.LEFT)
        
        # Sign In button
        ttk.Button(login_card, text="Sign In", style='Action.TButton',
                  command=lambda: self._do_login(user_entry.get(), pass_entry.get())
                  ).pack(fill=tk.X, pady=(0, 20))
        
        # Footer
        footer = tk.Frame(login_card, bg=colors['card_bg'])
        footer.pack(fill=tk.X, pady=(15, 0))
        
        tk.Label(footer, text="Version 2.5.0", font=('Segoe UI', 9),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(side=tk.LEFT)
        tk.Button(footer, text="Security Policy", font=('Segoe UI', 9, 'bold'), bg=colors['card_bg'],
                 fg=colors['accent'], relief='flat', cursor="hand2",
                 command=self._show_security_policy, activebackground=colors['card_bg']).pack(side=tk.RIGHT)
        
        user_entry.focus()
        user_entry.bind('<Return>', lambda e: self._do_login(user_entry.get(), pass_entry.get()))
        pass_entry.bind('<Return>', lambda e: self._do_login(user_entry.get(), pass_entry.get()))

    def _do_login(self, username, password):
        """Handle login authentication"""
        if not username or not password:
            messagebox.showerror("Login Failed", "Please enter both username and password")
            return
        
        res = self.db.authenticate_user(username, password)
        if res:
            self.current_user_id = res[0]
            self.current_username = username
            # Get user role from database
            # Get user role from database
            user_info = self.db.get_user_info(username)
            self.current_user_role = user_info[2] if user_info is not None and len(user_info) > 2 else 'user'
            self._show_main_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def _show_signup_page(self):
        """Self-service account creation"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        self.current_view = self._show_signup_page
        
        main_frame = tk.Frame(self.root, bg=colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left Panel
        left_panel = tk.Frame(main_frame, bg=colors['bg'], width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        left_panel.pack_propagate(False)
        
        branding = tk.Frame(left_panel, bg=colors['bg'])
        branding.pack(pady=(80, 50), padx=40, expand=True)
        
        tk.Label(branding, text="🛡️", font=('Segoe UI', 72), 
                bg=colors['bg'], fg=colors['accent']).pack()
        tk.Label(branding, text="Create Account", 
                font=('Segoe UI', 28, 'bold'), bg=colors['bg'], fg=colors['fg']).pack(pady=(15, 5))
        tk.Label(branding, text="Join Our Security Community", 
                font=('Segoe UI', 12), bg=colors['bg'], fg=colors['fg_secondary']).pack()
        
        # Right Panel
        right_panel = tk.Frame(main_frame, bg=colors['bg'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=50, pady=40)
        
        signup_card = tk.Frame(right_panel, bg=colors['card_bg'], padx=40, pady=40,
                             highlightthickness=1, highlightbackground=colors['card_border'])
        signup_card.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(signup_card, text="Create Your Account", font=('Segoe UI', 26, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(pady=(0, 25))
        
        # Username
        tk.Label(signup_card, text="Username", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        user_ent = ttk.Entry(signup_card, width=40)
        user_ent.pack(fill=tk.X, ipady=8, pady=(0, 15))
        
        # Email
        tk.Label(signup_card, text="Email Address", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        email_ent = ttk.Entry(signup_card, width=40)
        email_ent.pack(fill=tk.X, ipady=8, pady=(0, 15))
        
        # Password
        # Universal toggle function for this page
        def toggle_signup_vis(entry, btn):
            if entry.cget('show') == '•':
                entry.config(show='')
                btn.config(text='🙈')
            else:
                entry.config(show='•')
                btn.config(text='👁️')

        # Password
        tk.Label(signup_card, text="Password", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        pass_frame = tk.Frame(signup_card, bg=colors['card_bg'])
        pass_frame.pack(fill=tk.X, pady=(0, 15))
        
        pass_ent = ttk.Entry(pass_frame, show="•")
        pass_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        pass_btn = tk.Button(pass_frame, text="👁️", font=('Segoe UI', 11), bg=colors['bg_tertiary'], 
                            fg=colors['fg'], relief='flat', cursor="hand2", activebackground=colors['bg_secondary'])
        pass_btn.config(command=lambda: toggle_signup_vis(pass_ent, pass_btn))
        pass_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=5)
        
        # Confirm Password
        tk.Label(signup_card, text="Confirm Password", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        conf_frame = tk.Frame(signup_card, bg=colors['card_bg'])
        conf_frame.pack(fill=tk.X, pady=(0, 25))
        
        conf_ent = ttk.Entry(conf_frame, show="•")
        conf_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        conf_btn = tk.Button(conf_frame, text="👁️", font=('Segoe UI', 11), bg=colors['bg_tertiary'], 
                            fg=colors['fg'], relief='flat', cursor="hand2", activebackground=colors['bg_secondary'])
        conf_btn.config(command=lambda: toggle_signup_vis(conf_ent, conf_btn))
        conf_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=5)
        
        def do_signup():
            username = user_ent.get().strip()
            email = email_ent.get().strip()
            password = pass_ent.get()
            confirm = conf_ent.get()
            
            if not all([username, email, password, confirm]):
                messagebox.showerror("Error", "All fields are required")
                return
            
            if len(username) < 3:
                messagebox.showerror("Error", "Username must be at least 3 characters")
                return
            
            if '@' not in email:
                messagebox.showerror("Error", "Invalid email format")
                return
            
            if len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            if self.db.create_user(username, password, email):
                messagebox.showinfo("Success", "Account created! You can now log in.")
                self._show_login_page()
            else:
                messagebox.showerror("Error", "Username already exists")
        
        ttk.Button(signup_card, text="Create Account", style='Action.TButton', command=do_signup).pack(fill=tk.X, pady=(0, 10))
        tk.Button(signup_card, text="Back to Login", font=('Segoe UI', 10, 'bold'),
                 bg=colors['card_bg'], fg=colors['accent'], relief='flat', cursor="hand2",
                 command=self._show_login_page, activebackground=colors['card_bg']).pack(fill=tk.X)

    def _show_forgot_password(self):
        """Password recovery interface"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        self.current_view = self._show_forgot_password
        
        frame = tk.Frame(self.root, bg=colors['card_bg'], padx=40, pady=40,
                        highlightthickness=1, highlightbackground=colors['card_border'])
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        tk.Label(frame, text="🔐", font=('Segoe UI', 48), bg=colors['card_bg'], fg=colors['accent']).pack(pady=(0, 20))
        tk.Label(frame, text="Password Recovery", font=('Segoe UI', 24, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(pady=(0, 20))
        
        tk.Label(frame, text="Username", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        user_ent = ttk.Entry(frame, width=40)
        user_ent.pack(fill=tk.X, ipady=8, pady=(0, 25))
        
        def recover_email():
            username = user_ent.get()
            if not username:
                messagebox.showerror("Error", "Please enter username")
                return
            user_data = self.db.get_user_email(username)
            if not user_data:
                messagebox.showerror("Error", "Username not found")
                return
            messagebox.showinfo("Reset Email Sent", f"Password reset link sent to {user_data[1]}")
            self._show_login_page()
        
        def recover_questions():
            username = user_ent.get()
            if not username:
                messagebox.showerror("Error", "Please enter username")
                return
            user_id, questions = self.db.get_user_security_questions_for_recovery(username, count=2)
            if not questions:
                messagebox.showerror("Error", "No security questions set up")
                return
            self._show_password_recovery_questions(username, user_id, questions)
        
        b_frame = tk.Frame(frame, bg=colors['card_bg'])
        b_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(b_frame, text="Reset via Email", style='Action.TButton', command=recover_email).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(b_frame, text="Answer Security Questions", style='Secondary.TButton', command=recover_questions).pack(fill=tk.X, pady=(0, 10))
        tk.Button(b_frame, text="Back to Login", font=('Segoe UI', 10), bg=colors['card_bg'],
                 fg=colors['accent'], relief='flat', cursor="hand2",
                 command=self._show_login_page, activebackground=colors['card_bg']).pack(fill=tk.X)

    def _show_password_recovery_questions(self, username, user_id, questions):
        """Security questions for password recovery"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        
        frame = tk.Frame(self.root, bg=colors['card_bg'], padx=40, pady=40,
                        highlightthickness=1, highlightbackground=colors['card_border'])
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        tk.Label(frame, text="🔐", font=('Segoe UI', 36), bg=colors['card_bg']).pack(pady=(0, 15))
        tk.Label(frame, text="Answer Security Questions", font=('Segoe UI', 20, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(pady=(0, 20))
        
        entries = []
        for i, question in enumerate(questions):
            tk.Label(frame, text=f"Q{i+1}: {question}", font=('Segoe UI', 10, 'bold'),
                    bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(10, 5))
            ent = ttk.Entry(frame, width=40)
            ent.pack(fill=tk.X, py=(0, 15))
            entries.append(ent)
        
        def verify():
            answers = [e.get() for e in entries]
            if not all(answers):
                messagebox.showerror("Error", "Please answer all questions")
                return
            if self.db.verify_security_answers(user_id, answers):
                self._show_password_reset_form(user_id, username)
            else:
                messagebox.showerror("Error", "Incorrect answers")
        
        ttk.Button(frame, text="Verify & Reset", style='Action.TButton', command=verify).pack(fill=tk.X, pady=(20, 10))
        tk.Button(frame, text="Back", font=('Segoe UI', 10), bg=colors['card_bg'],
                 fg=colors['accent'], relief='flat', cursor="hand2",
                 command=self._show_forgot_password, activebackground=colors['card_bg']).pack(fill=tk.X)

    def _show_password_reset_form(self, user_id, username):
        """Password reset form"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        
        frame = tk.Frame(self.root, bg=colors['card_bg'], padx=40, pady=40,
                        highlightthickness=1, highlightbackground=colors['card_border'])
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        tk.Label(frame, text="🔑", font=('Segoe UI', 36), bg=colors['card_bg']).pack(pady=(0, 15))
        tk.Label(frame, text="Set New Password", font=('Segoe UI', 20, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(pady=(0, 20))
        
        tk.Label(frame, text="New Password", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        new_p = ttk.Entry(frame, width=40, show="•")
        new_p.pack(fill=tk.X, ipady=8, pady=(0, 15))
        
        tk.Label(frame, text="Confirm Password", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 8))
        conf_p = ttk.Entry(frame, width=40, show="•")
        conf_p.pack(fill=tk.X, ipady=8, pady=(0, 25))
        
        def reset():
            if new_p.get() != conf_p.get():
                messagebox.showerror("Error", "Passwords don't match")
                return
            if len(new_p.get()) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
            if self.db.update_user_password(user_id, new_p.get()):
                messagebox.showinfo("Success", "Password reset! You can now log in.")
                self._show_login_page()
            else:
                messagebox.showerror("Error", "Failed to reset password")
        
        ttk.Button(frame, text="Reset Password", style='Action.TButton', command=reset).pack(fill=tk.X, pady=(0, 10))
        tk.Button(frame, text="Back to Login", font=('Segoe UI', 10), bg=colors['card_bg'],
                 fg=colors['accent'], relief='flat', cursor="hand2",
                 command=self._show_login_page, activebackground=colors['card_bg']).pack(fill=tk.X)

    def _show_security_policy(self):
        """Display security policy"""
        policy = """IoT Guard Enterprise - Security Policy

Version 2.5.0

This application is designed for authorized security testing only.
All activities are logged and monitored.

Usage Restrictions:
• Only scan networks you own or have explicit permission
• Do not use for malicious activities
• All activities are subject to audit logging"""
        messagebox.showinfo("Security Policy", policy)

    # ===== MAIN DASHBOARD =====

    def _show_main_dashboard(self):
        """Main application dashboard with sidebar"""
        self._clear_root()
        colors = self.theme_colors
        self.root.configure(bg=colors['bg'])
        
        # Sidebar
        sidebar = tk.Frame(self.root, bg=colors['bg_secondary'], width=240)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Logo
        logo_frame = tk.Frame(sidebar, bg=colors['bg_secondary'], pady=20)
        logo_frame.pack(fill=tk.X)
        
        tk.Label(logo_frame, text="🛡️ IoT GUARD", font=('Segoe UI', 18, 'bold'),
                bg=colors['bg_secondary'], fg=colors['accent']).pack()
        tk.Label(logo_frame, text="Security Scanner", font=('Segoe UI', 9),
                bg=colors['bg_secondary'], fg=colors['fg_secondary']).pack()
        
        # Navigation
        nav_buttons = [
            ("📊 Dashboard", self._show_dashboard_view),
            ("🔍 New Scan", self._show_scan_view),
            ("📜 History", self._show_history_view),
            ("⚙️ Settings", self._show_settings_view)
        ]
        
        if self.current_user_role == 'admin':
            nav_buttons.append(("👥 Users", self._show_users_view))
            nav_buttons.append(("📞 Support Tickets", self._show_support_tickets_view))
        
        for text, cmd in nav_buttons:
            btn = tk.Button(sidebar, text=text, font=('Segoe UI', 11), bg=colors['bg_secondary'],
                           fg=colors['fg'], relief='flat', cursor="hand2", command=cmd,
                           activebackground=colors['bg_tertiary'], activeforeground=colors['accent'],
                           padx=15, pady=12, anchor=tk.W)
            btn.pack(fill=tk.X, padx=10, pady=5)
        
        # Spacer
        tk.Frame(sidebar, bg=colors['bg_secondary'], height=50).pack(fill=tk.BOTH, expand=True)
        
       # User info
        user_frame = tk.Frame(sidebar, bg=colors['bg_secondary'], pady=20)
        user_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(user_frame, text="👤", font=('Segoe UI', 16), bg=colors['bg_secondary']).pack()
        
        # FIXED LINE: Added str() conversion and fallback to satisfy Pylance
        tk.Label(user_frame, text=str(self.current_username or "Guest"), font=('Segoe UI', 10, 'bold'),
                bg=colors['bg_secondary'], fg=colors['fg'], wraplength=200).pack()
                
        tk.Label(user_frame, text=f"({self.current_user_role})", font=('Segoe UI', 8),
                bg=colors['bg_secondary'], fg=colors['fg_secondary']).pack()
        
        tk.Button(user_frame, text="Logout", font=('Segoe UI', 10, 'bold'),
                 bg=colors['error'], fg='white', relief='flat', cursor="hand2",
                 command=self._show_login_page, activebackground='#dc2626').pack(pady=(10, 0))
        
        # Content area
        self.content_area = tk.Frame(self.root, bg=colors['bg'])
        self.content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self._show_dashboard_view()

    def _show_dashboard_view(self):
        """Dashboard with summary statistics"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_dashboard_view
        
        header = tk.Frame(self.content_area, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text="Dashboard", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        tk.Label(header, text=f"Welcome, {self.current_username}",
                font=('Segoe UI', 12), bg=colors['bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(5, 0))
        
        # Summary stats
        stats = self.db.get_dashboard_summary(self.current_user_id)
        
        stats_frame = tk.Frame(self.content_area, bg=colors['bg'])
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        stat_cards = [
            ("Total Scans", stats['total_scans'], "📋", colors['accent']),
            ("Devices Found", stats['total_devices'], "💻", "#3b82f6"),
            ("Critical/High", stats['total_high'], "🚫", colors['error']),
            ("Medium Risk", stats['total_med'], "⚠️", colors['warning'])
        ]
        
        for title, value, icon, color in stat_cards:
            self._create_stat_card(stats_frame, title, value, icon, color)
        
        # Network status and quick actions
        row2 = tk.Frame(self.content_area, bg=colors['bg'])
        row2.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Network status card
        status_card = tk.Frame(row2, bg=colors['card_bg'], padx=20, pady=20,
                             highlightthickness=1, highlightbackground=colors['card_border'])
        status_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        tk.Label(status_card, text="NETWORK STATUS", font=('Segoe UI', 10, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        ssid = IoTVulnerabilityScanner.get_current_ssid() or "Not Connected"
        status_color = colors['success'] if ssid != "Not Connected" else colors['error']
        status_icon = "●" if ssid != "Not Connected" else "○"
        
        tk.Label(status_card, text=f"SSID: {ssid}", font=('Segoe UI', 11),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=5)
        tk.Label(status_card, text=f"{status_icon} {'Online' if ssid != 'Not Connected' else 'Offline'}",
                font=('Segoe UI', 11, 'bold'), bg=colors['card_bg'], fg=status_color).pack(anchor=tk.W)
        
        # Quick actions card
        actions_card = tk.Frame(row2, bg=colors['card_bg'], padx=20, pady=20,
                              highlightthickness=1, highlightbackground=colors['card_border'])
        actions_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        tk.Label(actions_card, text="QUICK ACTIONS", font=('Segoe UI', 10, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Button(actions_card, text="🚀 Start New Scan", style='Action.TButton',
                  command=self._show_scan_view).pack(fill=tk.X, pady=(0, 10))
        ttk.Button(actions_card, text="📄 View History", style='Secondary.TButton',
                  command=self._show_history_view).pack(fill=tk.X)

    def _create_stat_card(self, parent, title, value, icon, color):
        """Create a modern stat card"""
        colors = self.theme_colors
        
        card = tk.Frame(parent, bg=colors['card_bg'], padx=20, pady=15,
                       highlightthickness=1, highlightbackground=colors['card_border'])
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        tk.Label(card, text=icon, font=('Segoe UI', 18), bg=colors['card_bg']).pack(anchor=tk.W, pady=(0, 5))
        tk.Label(card, text=str(value), font=('Segoe UI', 28, 'bold'),
                bg=colors['card_bg'], fg=color).pack(anchor=tk.W)
        tk.Label(card, text=title, font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(5, 0))

    def _show_scan_view(self):
        """Live scanning interface - preserves all original backend logic"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_scan_view
        
        header = tk.Frame(self.content_area, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text="New Security Scan", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        # Configuration card
        config_card = tk.Frame(self.content_area, bg=colors['card_bg'], padx=20, pady=20,
                             highlightthickness=1, highlightbackground=colors['card_border'])
        config_card.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(config_card, text="SCAN CONFIGURATION", font=('Segoe UI', 10, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        tk.Label(config_card, text="Target Selection", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 10))
        
        self.scan_mode = tk.StringVar(value="WiFi")
        ttk.Radiobutton(config_card, text="Active WiFi Network", variable=self.scan_mode, 
                       value="WiFi").pack(anchor=tk.W, pady=3)
        ttk.Radiobutton(config_card, text="Custom Subnet", variable=self.scan_mode,
                       value="Subnet").pack(anchor=tk.W, pady=3)
        
        tk.Label(config_card, text="Target Subnet", font=('Segoe UI', 10, 'bold'),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(15, 5))
        
        settings = self.db.get_user_settings(self.current_user_id) or {}
        self.subnet_ent = ttk.Entry(config_card, width=50)
        self.subnet_ent.insert(0, settings.get('default_subnet', '192.168.1.0/24'))
        self.subnet_ent.pack(fill=tk.X, pady=(0, 20), ipady=6)
        
        btn_frame = tk.Frame(config_card, bg=colors['card_bg'])
        btn_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(btn_frame, text="▶ Start Scan", style='Action.TButton',
                                   command=self._start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(btn_frame, text="🛑 Stop Scan", style='Secondary.TButton',
                                  state='disabled', command=self._stop_scan)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Progress section
        progress_card = tk.Frame(self.content_area, bg=colors['card_bg'], padx=20, pady=20,
                               highlightthickness=1, highlightbackground=colors['card_border'])
        progress_card.pack(fill=tk.X, pady=(0, 20))
        
        self.status_lbl = tk.Label(progress_card, text="Ready to scan", 
                                  font=('Segoe UI', 11, 'bold'),
                                  bg=colors['card_bg'], fg=colors['fg'])
        self.status_lbl.pack(anchor=tk.W, pady=(0, 10))
        
        self.pb = ttk.Progressbar(progress_card, mode='determinate')
        self.pb.pack(fill=tk.X)
        
        # Results table
        results_header = tk.Frame(self.content_area, bg=colors['bg'])
        results_header.pack(fill=tk.X, pady=(20, 10))
        
        tk.Label(results_header, text="DISCOVERED DEVICES", font=('Segoe UI', 11, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        tree_frame = tk.Frame(self.content_area, bg=colors['bg'])
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("IP Address", "MAC", "Hostname", "Vendor", "Status")
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=150)
        
        self.device_tree.tag_configure('oddrow', background=colors['card_bg'])
        self.device_tree.tag_configure('evenrow', background=colors['bg'])
        
        self.device_tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.configure(yscrollcommand=scrollbar.set)

    def _start_scan(self):
        """Start scan - PRESERVES ALL ORIGINAL BACKEND LOGIC"""
        mode = self.scan_mode.get()
        target = ""
        
        if mode == "WiFi":
            ssid = IoTVulnerabilityScanner.get_current_ssid()
            if not ssid:
                messagebox.showerror("Error", "No WiFi detected")
                return
            target = ssid
            detected_subnet = IoTVulnerabilityScanner.get_wifi_subnet()
            subnet = detected_subnet if detected_subnet else self.subnet_ent.get()
        else:
            subnet = self.subnet_ent.get().strip()
            if not subnet:
                messagebox.showerror("Error", "Please enter target subnet")
                return
            target = subnet
        
        # Validate subnet
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            if net.prefixlen < 22:
                if not messagebox.askyesno("Large Subnet", f"This subnet contains {net.num_addresses} addresses.\nContinue?"):
                    return
        except ValueError:
            messagebox.showerror("Error", f"Invalid subnet: {subnet}")
            return
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.pb['value'] = 0
        self.status_lbl.config(text="Starting scan...")
        
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        self.stop_event.clear()
        self.scan_thread = threading.Thread(target=self._run_scan_worker, 
                                          args=(subnet, mode, target), daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        """Stop the running scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.status_lbl.config(text="Stopping scan...")
            self.stop_btn.config(state=tk.DISABLED)

    def _run_scan_worker(self, subnet, mode, target):
        """ORIGINAL BACKEND LOGIC - COMPLETELY PRESERVED"""
        try:
            def progress_update(percentage, message):
                try:
                    self.root.after(0, self._update_progress_ui, percentage, message)
                except (tk.TclError, RuntimeError):
                    pass
            
            self.scanner = IoTVulnerabilityScanner(subnet=subnet)
            self.last_results = self.scanner.run_scan(
                stop_event=self.stop_event,
                progress_callback=progress_update
            )
            
            if not self.stop_event.is_set():
                self.db.add_scan_record(self.current_user_id, mode, target, self.last_results)
                try:
                    self.root.after(0, self._scan_complete, True)
                except (tk.TclError, RuntimeError):
                    pass
            else:
                try:
                    self.root.after(0, self._scan_complete, False, "Scan stopped")
                except (tk.TclError, RuntimeError):
                    pass
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            try:
                self.root.after(0, self._scan_complete, False, str(e))
            except (tk.TclError, RuntimeError):
                pass

    def _update_progress_ui(self, percentage, message):
        """ORIGINAL LOGIC PRESERVED - UI queue safe updates"""
        try:
            if not self.pb.winfo_exists():
                return
            self.pb['value'] = percentage
            self.status_lbl.config(text=message)
            
            if self.scanner and hasattr(self.scanner, 'results_so_far'):
                results = self.scanner.results_so_far
                if 'devices' in results and self.device_tree.winfo_exists():
                    current_items = {self.device_tree.item(i)['values'][0]: i 
                                   for i in self.device_tree.get_children()}
                    for d in results['devices'].values():
                        ip = d['ip']
                        if ip not in current_items:
                            tag = 'oddrow' if len(self.device_tree.get_children()) % 2 == 0 else 'evenrow'
                            self.device_tree.insert("", tk.END, values=(
                                ip,
                                d.get('mac', 'Unknown'),
                                d.get('hostname', 'Unknown'),
                                d.get('manufacturer', 'Unknown'),
                                "⏳ Analyzing..."
                            ), tags=(tag,))
        except (tk.TclError, RuntimeError):
            pass

    def _scan_complete(self, success, msg=None):
        """ORIGINAL LOGIC PRESERVED - Final results display"""
        try:
            if self.start_btn.winfo_exists():
                self.start_btn.config(state=tk.NORMAL)
            if self.stop_btn.winfo_exists():
                self.stop_btn.config(state=tk.DISABLED)
            
            if success:
                if self.pb.winfo_exists():
                    self.pb['value'] = 100
                if self.status_lbl.winfo_exists():
                    self.status_lbl.config(text="Scan complete!")
                
                if self.device_tree.winfo_exists():
                    for item in self.device_tree.get_children():
                        self.device_tree.delete(item)
                    
                    posture = (self.last_results or {}).get('security_posture', [])
                    for idx, p in enumerate(posture):
                        risk_lvl = p.get('risk_level', 'Low')
                        risk_score = p.get('risk_score', 0)
                        
                        if risk_lvl == 'Low' and not p.get('open_ports'):
                            continue
                        
                        status_text = f"{risk_lvl} ({risk_score:.1f}/100)"
                        tag = 'oddrow' if idx % 2 == 0 else 'evenrow'
                        
                        self.device_tree.insert("", tk.END, values=(
                            p['ip'],
                            p['mac'],
                            p.get('hostname', 'Unknown'),
                            p.get('vendor', 'Unknown'),
                            status_text
                        ), tags=(tag,))
                
                messagebox.showinfo("Success", "Scan complete!")
        except (tk.TclError, RuntimeError):
            pass

    def _show_history_view(self):
        """Scan history with search/filter"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_history_view
        
        header = tk.Frame(self.content_area, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text="Scan History", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        # Search bar
        search_frame = tk.Frame(self.content_area, bg=colors['bg'])
        search_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(search_frame, text="🔍 Search:", font=('Segoe UI', 10),
                bg=colors['bg'], fg=colors['fg']).pack(side=tk.LEFT, padx=(0, 10))
        
        search_var = tk.StringVar()
        search_ent = ttk.Entry(search_frame, width=50)
        search_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        
        # History table
        columns = ("Date", "Type", "Target", "Devices", "High", "Medium")
        tree = ttk.Treeview(self.content_area, columns=columns, show='headings', height=10)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        tree.tag_configure('oddrow', background=colors['card_bg'])
        tree.tag_configure('evenrow', background=colors['bg'])
        
        def load_history(search=""):
            for item in tree.get_children():
                tree.delete(item)
            
            history = self.db.get_scan_history(self.current_user_id)
            for idx, h in enumerate(history):
                if search.lower() in str(h['target']).lower() or search.lower() in h['scan_type'].lower():
                    tag = 'oddrow' if idx % 2 == 0 else 'evenrow'
                    tree.insert("", tk.END, values=(
                        h['timestamp'],
                        h['scan_type'],
                        h['target'],
                        h['device_count'],
                        h['vuln_high'],
                        h['vuln_med']
                    ), tags=(tag,))
        
        search_ent.bind("<KeyRelease>", lambda e: load_history(search_ent.get()))
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.content_area, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        
        load_history()

    def _show_settings_view(self):
        """User settings and preferences with scrollable content"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_settings_view
        
        # Create scrollable canvas
        canvas = tk.Canvas(self.content_area, bg=colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.content_area, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=colors['bg'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Header
        header = tk.Frame(scrollable_frame, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20), padx=20)
        
        tk.Label(header, text="Settings", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        # Theme toggle card
        theme_card = tk.Frame(scrollable_frame, bg=colors['card_bg'], padx=20, pady=20,
                            highlightthickness=1, highlightbackground=colors['card_border'])
        theme_card.pack(fill=tk.X, pady=(0, 20), padx=20)
        
        tk.Label(theme_card, text="⚙️ APPEARANCE", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        theme_frame = tk.Frame(theme_card, bg=colors['card_bg'])
        theme_frame.pack(anchor=tk.W)
        
        tk.Label(theme_frame, text="Theme:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Label(theme_frame, text="Dark" if self.is_dark_theme else "Light", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['accent']).pack(side=tk.LEFT)
        
        ttk.Button(theme_card, text="Toggle Theme", style='Secondary.TButton',
                  command=self._toggle_theme).pack(anchor=tk.W, pady=(15, 0))
        
        # Scan settings card
        scan_card = tk.Frame(scrollable_frame, bg=colors['card_bg'], padx=20, pady=20,
                           highlightthickness=1, highlightbackground=colors['card_border'])
        scan_card.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(scan_card, text="🔍 SCAN SETTINGS", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        settings = self.db.get_user_settings(self.current_user_id) or {}
        
        tk.Label(scan_card, text="Default Subnet:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        
        subnet_ent = ttk.Entry(scan_card, width=50)
        subnet_ent.insert(0, settings.get('default_subnet', '192.168.1.0/24'))
        subnet_ent.pack(fill=tk.X, ipady=6, pady=(0, 15))
        
        tk.Label(scan_card, text="Email Address:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        
        email_ent = ttk.Entry(scan_card, width=50)
        user_email = self.db.get_user_email(self.current_user_id)
        email_ent.insert(0, user_email if user_email else "")
        email_ent.pack(fill=tk.X, ipady=6, pady=(0, 20))
        
        def save_settings():
            subnet = subnet_ent.get()
            email = email_ent.get()
            
            # Validate email if provided
            if email and '@' not in email:
                messagebox.showerror("Error", "Please enter a valid email address")
                return
            
            self.db.update_user_settings(self.current_user_id, subnet, None, None)
            if email:
                self.db.update_user_email(self.current_user_id, email)
            messagebox.showinfo("Success", "Settings and email saved!")
        
        ttk.Button(scan_card, text="Save Settings", style='Action.TButton',
                  command=save_settings).pack(anchor=tk.W)
        
        # Password change card
        pwd_card = tk.Frame(scrollable_frame, bg=colors['card_bg'], padx=20, pady=20,
                           highlightthickness=1, highlightbackground=colors['card_border'])
        pwd_card.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(pwd_card, text="🔐 CHANGE PASSWORD", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
       # Universal toggle function for settings
        def toggle_settings_vis(entry, btn):
            if entry.cget('show') == '•':
                entry.config(show='')
                btn.config(text='🙈')
            else:
                entry.config(show='•')
                btn.config(text='👁️')

        # Current Password
        tk.Label(pwd_card, text="Current Password:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        cp_frame = tk.Frame(pwd_card, bg=colors['card_bg'])
        cp_frame.pack(fill=tk.X, pady=(0, 15))
        
        current_pwd_ent = ttk.Entry(cp_frame, show='•')
        current_pwd_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        cp_btn = tk.Button(cp_frame, text="👁️", font=('Segoe UI', 10), bg=colors['bg_tertiary'], 
                          fg=colors['fg'], relief='flat', cursor="hand2", activebackground=colors['bg_secondary'])
        cp_btn.config(command=lambda: toggle_settings_vis(current_pwd_ent, cp_btn))
        cp_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=3)
        
        # New Password
        tk.Label(pwd_card, text="New Password:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        np_frame = tk.Frame(pwd_card, bg=colors['card_bg'])
        np_frame.pack(fill=tk.X, pady=(0, 15))
        
        new_pwd_ent = ttk.Entry(np_frame, show='•')
        new_pwd_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        np_btn = tk.Button(np_frame, text="👁️", font=('Segoe UI', 10), bg=colors['bg_tertiary'], 
                          fg=colors['fg'], relief='flat', cursor="hand2", activebackground=colors['bg_secondary'])
        np_btn.config(command=lambda: toggle_settings_vis(new_pwd_ent, np_btn))
        np_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=3)
        
        # Confirm Password
        tk.Label(pwd_card, text="Confirm Password:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        confp_frame = tk.Frame(pwd_card, bg=colors['card_bg'])
        confp_frame.pack(fill=tk.X, pady=(0, 20))
        
        confirm_pwd_ent = ttk.Entry(confp_frame, show='•')
        confirm_pwd_ent.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        confp_btn = tk.Button(confp_frame, text="👁️", font=('Segoe UI', 10), bg=colors['bg_tertiary'], 
                             fg=colors['fg'], relief='flat', cursor="hand2", activebackground=colors['bg_secondary'])
        confp_btn.config(command=lambda: toggle_settings_vis(confirm_pwd_ent, confp_btn))
        confp_btn.pack(side=tk.RIGHT, padx=(5, 0), ipadx=8, ipady=3)
        
        def change_password():
            current_pwd = current_pwd_ent.get()
            new_pwd = new_pwd_ent.get()
            confirm_pwd = confirm_pwd_ent.get()
            
            if not current_pwd or not new_pwd or not confirm_pwd:
                messagebox.showerror("Error", "All fields are required")
                return
            
            if new_pwd != confirm_pwd:
                messagebox.showerror("Error", "New passwords do not match")
                return
            
            if len(new_pwd) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long")
                return
            
            # Verify current password
            res = self.db.authenticate_user(self.current_username, current_pwd)
            if not res:
                messagebox.showerror("Error", "Current password is incorrect")
                return
            
            # Change password
            if self.db.change_password(self.current_user_id, new_pwd):
                messagebox.showinfo("Success", "Password changed successfully!")
                current_pwd_ent.delete(0, tk.END)
                new_pwd_ent.delete(0, tk.END)
                confirm_pwd_ent.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Failed to change password")
        
        ttk.Button(pwd_card, text="Change Password", style='Action.TButton',
                  command=change_password).pack(anchor=tk.W)
        
        # Customer support card
        support_card = tk.Frame(scrollable_frame, bg=colors['card_bg'], padx=20, pady=20,
                               highlightthickness=1, highlightbackground=colors['card_border'])
        support_card.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        tk.Label(support_card, text="📞 CUSTOMER SUPPORT", font=('Segoe UI', 11, 'bold'),
                bg=colors['card_bg'], fg=colors['fg_secondary']).pack(anchor=tk.W, pady=(0, 15))
        
        tk.Label(support_card, text="Subject:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        support_subject_ent = ttk.Entry(support_card, width=50)
        support_subject_ent.pack(fill=tk.X, ipady=6, pady=(0, 15))
        
        tk.Label(support_card, text="Message:", font=('Segoe UI', 10),
                bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(0, 5))
        support_msg_text = tk.Text(support_card, height=5, width=50, font=('Segoe UI', 10),
                                   bg=colors['card_bg'], fg=colors['fg'])
        support_msg_text.pack(fill=tk.X, ipady=6, pady=(0, 20))
        
        def submit_support():
            subject = support_subject_ent.get()
            message = support_msg_text.get("1.0", tk.END).strip()
            
            if not subject or not message:
                messagebox.showerror("Error", "Subject and message are required")
                return
            
            if self.db.create_support_message(self.current_user_id, subject, message):
                messagebox.showinfo("Success", "Support request submitted! Admin will respond soon.")
                support_subject_ent.delete(0, tk.END)
                support_msg_text.delete("1.0", tk.END)
            else:
                messagebox.showerror("Error", "Failed to submit support request")
        
        ttk.Button(support_card, text="Submit Support Request", style='Action.TButton',
                  command=submit_support).pack(anchor=tk.W, pady=(0, 10))
        
        # Display existing support tickets
        support_tickets = self.db.get_support_messages(self.current_user_id)
        if support_tickets:
            tk.Label(support_card, text="Previous Requests:", font=('Segoe UI', 9, 'bold'),
                    bg=colors['card_bg'], fg=colors['fg']).pack(anchor=tk.W, pady=(10, 5))
            
            for ticket in support_tickets:
                status_color = colors['success'] if ticket['status'] == 'Resolved' else colors['warning']
                ticket_frame = tk.Frame(support_card, bg=colors['card_bg'])
                ticket_frame.pack(fill=tk.X, pady=3)
                
                tk.Label(ticket_frame, text=f"• {ticket['subject']}", font=('Segoe UI', 9),
                        bg=colors['card_bg'], fg=colors['fg']).pack(side=tk.LEFT, anchor=tk.W)
                tk.Label(ticket_frame, text=f"[{ticket['status']}]", font=('Segoe UI', 9),
                        bg=colors['card_bg'], fg=status_color).pack(side=tk.RIGHT)

    def _show_users_view(self):
        """Admin user management"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_users_view
        
        header = tk.Frame(self.content_area, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text="User Management", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        # Users table
        columns = ("No.", "Username", "Role", "Email", "Created")
        tree = ttk.Treeview(self.content_area, columns=columns, show='headings', height=10)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        tree.tag_configure('oddrow', background=colors['card_bg'])
        tree.tag_configure('evenrow', background=colors['bg'])
        
        users = self.db.get_all_users()
        for idx, u in enumerate(users, 1):
            tag = 'oddrow' if idx % 2 == 0 else 'evenrow'
            tree.insert("", tk.END, iid=str(u['id']), values=(
                idx, u['username'], u.get('role', 'user'), 
                u.get('email', 'N/A'), u.get('created_at', 'N/A')
            ), tags=(tag,))
        
        tree.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        scrollbar = ttk.Scrollbar(self.content_area, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Buttons
        btn_frame = tk.Frame(self.content_area, bg=colors['bg'])
        btn_frame.pack(fill=tk.X)
        
        def delete_user():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select a user")
                return
            user_id = int(selected[0])
            if user_id == self.current_user_id:
                messagebox.showerror("Error", "Cannot delete yourself")
                return
            if messagebox.askyesno("Confirm", "Delete this user?"):
                self.db.delete_user(user_id)
                self._show_users_view()
        
        ttk.Button(btn_frame, text="Delete Selected", style='Secondary.TButton',
                  command=delete_user).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Refresh", style='Secondary.TButton',
                  command=self._show_users_view).pack(side=tk.LEFT)

    def _show_support_tickets_view(self):
        """Admin support ticket management"""
        self._clear_widgets(self.content_area)
        colors = self.theme_colors
        self.current_view = self._show_support_tickets_view
        
        header = tk.Frame(self.content_area, bg=colors['bg'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text="Support Tickets", font=('Segoe UI', 24, 'bold'),
                bg=colors['bg'], fg=colors['fg']).pack(anchor=tk.W)
        
        # Support tickets table
        columns = ("No.", "User", "Subject", "Status", "Created")
        tree = ttk.Treeview(self.content_area, columns=columns, show='headings', height=12)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200 if col == "Subject" else 150)
        
        tree.tag_configure('oddrow', background=colors['card_bg'])
        tree.tag_configure('evenrow', background=colors['bg'])
        tree.tag_configure('open', foreground=colors['warning'])
        tree.tag_configure('resolved', foreground=colors['success'])
        tree.tag_configure('in_progress', foreground=colors['accent'])
        
        tickets = self.db.get_support_messages()
        for idx, ticket in enumerate(tickets, 1):
            tag = 'oddrow' if idx % 2 == 0 else 'evenrow'
            status_tag = ticket['status'].lower().replace(' ', '_')
            tree.insert("", tk.END, iid=str(ticket['id']), values=(
                idx, ticket['username'], ticket['subject'], 
                ticket['status'], ticket['created_at']
            ), tags=(tag, status_tag))
        
        tree.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        scrollbar = ttk.Scrollbar(self.content_area, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Buttons and details
        btn_frame = tk.Frame(self.content_area, bg=colors['bg'])
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Details frame
        details_frame = tk.Frame(self.content_area, bg=colors['card_bg'], padx=15, pady=15,
                                highlightthickness=1, highlightbackground=colors['card_border'])
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        details_text = tk.Text(details_frame, height=6, width=80, font=('Segoe UI', 10),
                               bg=colors['card_bg'], fg=colors['fg'])
        details_text.pack(fill=tk.BOTH, expand=True)
        details_text.config(state=tk.DISABLED)
        
        def show_ticket_details():
            selected = tree.selection()
            if not selected:
                details_text.config(state=tk.NORMAL)
                details_text.delete("1.0", tk.END)
                details_text.insert("1.0", "Select a ticket to view details")
                details_text.config(state=tk.DISABLED)
                return
            
            ticket_id = int(selected[0])
            for ticket in tickets:
                if ticket['id'] == ticket_id:
                    details_text.config(state=tk.NORMAL)
                    details_text.delete("1.0", tk.END)
                    details = f"User: {ticket['username']}\nSubject: {ticket['subject']}\nStatus: {ticket['status']}\nCreated: {ticket['created_at']}\n\nMessage:\n{ticket['message']}"
                    details_text.insert("1.0", details)
                    details_text.config(state=tk.DISABLED)
                    break
        
        def update_status(new_status):
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select a ticket")
                return
            ticket_id = int(selected[0])
            if self.db.update_message_status(ticket_id, new_status):
                messagebox.showinfo("Success", f"Ticket status updated to {new_status}")
                self._show_support_tickets_view()
            else:
                messagebox.showerror("Error", "Failed to update ticket status")
        
        ttk.Button(btn_frame, text="View Details", style='Secondary.TButton',
                  command=show_ticket_details).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Mark In Progress", style='Secondary.TButton',
                  command=lambda: update_status("In Progress")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Mark Resolved", style='Action.TButton',
                  command=lambda: update_status("Resolved")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Refresh", style='Secondary.TButton',
                  command=self._show_support_tickets_view).pack(side=tk.LEFT)

    def _clear_widgets(self, parent):
        """Clear all widgets from a parent"""
        for widget in parent.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()
    app = IoTScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
    
    