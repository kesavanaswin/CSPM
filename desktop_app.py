import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

ROOT = Path(__file__).resolve().parent


class CSPMLoginWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CSPM Secure Login")
        self.root.geometry("420x240")
        self.root.resizable(False, False)

        ttk.Label(
            root,
            text="Container Security Posture Management",
            font=("Segoe UI", 14, "bold"),
        ).pack(pady=(18, 8))

        ttk.Label(root, text="Username").pack(anchor="w", padx=30)
        self.username = ttk.Entry(root, width=35)
        self.username.insert(0, "admin")
        self.username.pack(padx=30, pady=(0, 10))

        ttk.Label(root, text="Password").pack(anchor="w", padx=30)
        self.password = ttk.Entry(root, width=35, show="*")
        self.password.insert(0, "admin123")
        self.password.pack(padx=30, pady=(0, 16))

        ttk.Button(root, text="Login", command=self.login).pack(fill="x", padx=30)

    def login(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if username == "admin" and password == "admin123":
            self.root.destroy()
            self.open_main_app()
        else:
            messagebox.showerror("Login failed", "Invalid username or password.")

    def open_main_app(self):
        app_root = tk.Tk()
        CSPMDesktopApp(app_root)
        app_root.mainloop()


class CSPMDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CSPM Security Console")
        self.root.geometry("460x220")
        self.root.resizable(False, False)

        title = ttk.Label(
            root,
            text="Container Security Posture Management",
            font=("Segoe UI", 14, "bold"),
        )
        title.pack(pady=(16, 10))

        subtitle = ttk.Label(
            root,
            text="Choose an interface to launch.",
            font=("Segoe UI", 10),
        )
        subtitle.pack(pady=(0, 14))

        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=6)

        ttk.Button(
            btn_frame,
            text="Run CLI Scan",
            width=22,
            command=self.run_cli,
        ).grid(row=0, column=0, padx=8, pady=6)

        ttk.Button(
            btn_frame,
            text="Open Dashboard",
            width=22,
            command=self.run_dashboard,
        ).grid(row=0, column=1, padx=8, pady=6)

        ttk.Button(
            btn_frame,
            text="Exit",
            width=22,
            command=self.root.destroy,
        ).grid(row=1, column=0, columnspan=2, pady=(8, 0))

    def _start_process(self, command: list[str], label: str):
        try:
            subprocess.Popen(command, cwd=str(ROOT), shell=False)
            messagebox.showinfo("Started", f"{label} started successfully.")
        except Exception as exc:
            messagebox.showerror("Launch failed", f"Unable to start {label}:\n{exc}")

    def run_cli(self):
        self._start_process([sys.executable, "main.py", "--mode", "demo"], "CSPM CLI")

    def run_dashboard(self):
        self._start_process(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "dashboard.py",
                "--server.headless",
                "true",
                "--server.port",
                "8501",
            ],
            "CSPM Dashboard",
        )


def main():
    root = tk.Tk()
    CSPMLoginWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
