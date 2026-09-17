"""Grey terminal-style GUI for the password strength checker."""

import queue
import threading
import tkinter as tk
from tkinter import font as tkfont

import strength

CHROME = "#2b2b2b"
BG = "#3a3a3a"
RULE = "#555555"
FG = "#dcdcdc"
DIM = "#9a9a9a"
PROMPT = "#b8d8b8"
COLORS = {"good": "#9fd49f", "warn": "#e6c67a", "bad": "#f08c82"}

MONO_FONTS = ("Cascadia Mono", "Consolas", "Menlo", "DejaVu Sans Mono", "Courier New")

IDLE_TEXT = [
    [("  Type a password to analyse it live. Nothing is stored or logged.", None)],
    [],
    [("  Enter  ", "title"), ("  full check, including the Have I Been Pwned breach lookup", "dim")],
    [("  Ctrl+R ", "title"), ("  show / hide password and matched fragments", "dim")],
    [("  Esc    ", "title"), ("  clear", "dim")],
    [("  Ctrl+Q ", "title"), ("  quit", "dim")],
    [],
    [("  Breach lookups use k-anonymity: only the first 5 characters of the", "dim")],
    [("  password's SHA-1 hash are sent to api.pwnedpasswords.com.", "dim")],
]


def pick_mono_font(root):
    available = set(tkfont.families(root))
    return next((name for name in MONO_FONTS if name in available), "TkFixedFont")


class TerminalApp:
    def __init__(self, root):
        self.root = root
        self.reveal = False
        self.generation = 0  # bumped on every edit so stale breach results are ignored
        self.breach = None
        self.render_job = None
        self.results = queue.Queue()

        family = pick_mono_font(root)
        self.font = (family, 11)
        self.bold = (family, 11, "bold")

        root.title("Password Checker v2.0")
        root.geometry("860x780")
        root.minsize(560, 420)
        root.configure(bg=CHROME)

        self._build_chrome()
        self._build_body()
        self._bind_keys()

        self.render()
        self.entry.focus_set()
        self.root.after(100, self._poll_results)

    # ------------------------------------------------------------------ layout

    def _build_chrome(self):
        bar = tk.Frame(self.root, bg=CHROME)
        bar.pack(fill="x")
        dots = tk.Label(bar, text="●  ●  ●", bg=CHROME, fg="#6e6e6e", font=self.font)
        dots.pack(side="left", padx=12, pady=6)
        tk.Label(bar, text="pwcheck — password strength terminal", bg=CHROME, fg=DIM,
                 font=self.font).pack(side="left", expand=True)
        tk.Label(bar, text="v2.0", bg=CHROME, fg="#6e6e6e", font=self.font).pack(side="right", padx=12)

    def _build_body(self):
        body = tk.Frame(self.root, bg=BG, padx=18, pady=10)
        body.pack(fill="both", expand=True)

        tk.Label(body, text=strength.BANNER.strip("\n"), justify="left", anchor="w",
                 bg=BG, fg=DIM, font=self.font).pack(fill="x")

        row = tk.Frame(body, bg=BG)
        row.pack(fill="x", pady=(12, 6))
        tk.Label(row, text="user@pwcheck", bg=BG, fg=PROMPT, font=self.bold).pack(side="left")
        tk.Label(row, text=":~$ password ", bg=BG, fg=FG, font=self.font).pack(side="left")

        self.password = tk.StringVar()
        self.password.trace_add("write", self._on_change)
        self.entry = tk.Entry(row, textvariable=self.password, show="•", bg=BG, fg=FG,
                              insertbackground=FG, insertwidth=8, relief="flat",
                              highlightthickness=0, selectbackground=RULE, font=self.font)
        self.entry.pack(side="left", fill="x", expand=True)

        self.toggle = tk.Label(row, text="[show]", bg=BG, fg=DIM, font=self.font, cursor="hand2")
        self.toggle.pack(side="right")
        self.toggle.bind("<Button-1>", lambda e: self.toggle_reveal())

        tk.Frame(body, bg=RULE, height=1).pack(fill="x", pady=(2, 8))

        self.output = tk.Text(body, bg=BG, fg=FG, relief="flat", highlightthickness=0, wrap="word",
                              font=self.font, cursor="arrow", selectbackground=RULE, borderwidth=0)
        self.output.pack(fill="both", expand=True)
        for style, color in COLORS.items():
            self.output.tag_configure(style, foreground=color)
        self.output.tag_configure("dim", foreground=DIM)
        self.output.tag_configure("head", foreground="#c4c4c4", font=self.bold)
        self.output.tag_configure("title", foreground=CHROME, background="#c8c8c8", font=self.bold)

        self.status = tk.Label(self.root, text="", anchor="w", bg=CHROME, fg=DIM, font=self.font, padx=12, pady=4)
        self.status.pack(fill="x")

    def _bind_keys(self):
        self.entry.bind("<Return>", lambda e: self.run_breach_check())
        self.entry.bind("<KP_Enter>", lambda e: self.run_breach_check())
        self.root.bind("<Escape>", lambda e: self.password.set(""))
        self.root.bind("<Control-r>", lambda e: self.toggle_reveal() or "break")
        self.root.bind("<Control-q>", lambda e: self.quit())
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    # ----------------------------------------------------------------- actions

    def _on_change(self, *_):
        self.generation += 1
        self.breach = None
        if self.render_job:
            self.root.after_cancel(self.render_job)
        self.render_job = self.root.after(120, self.render)

    def toggle_reveal(self):
        self.reveal = not self.reveal
        self.entry.configure(show="" if self.reveal else "•")
        self.toggle.configure(text="[hide]" if self.reveal else "[show]")
        self.render()

    def run_breach_check(self):
        password = self.password.get()
        if not password or self.breach is not None:
            return
        self.breach = "checking"
        self.render()
        generation = self.generation

        def worker():
            self.results.put((generation, strength.check_breach(password)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_results(self):
        # Tk isn't thread-safe, so worker threads hand results back through a queue.
        while not self.results.empty():
            generation, result = self.results.get_nowait()
            if generation == self.generation:
                self.breach = result
                self.render()
        self.root.after(100, self._poll_results)

    def quit(self):
        self.password.set("")
        self.root.destroy()

    # ------------------------------------------------------------------ output

    def render(self):
        self.render_job = None
        password = self.password.get()
        if not password:
            lines = IDLE_TEXT
            self.status.configure(text=" waiting for input")
        else:
            analysis = strength.analyze(password)
            lines = strength.build_report(analysis, self.breach, self.reveal,
                                          breach_hint="press Enter to check against known breaches")
            self.status.configure(text=f" {analysis.length} chars · {analysis.effective_entropy:.1f} bits · "
                                       "Enter: breach check · Ctrl+R: show/hide · Esc: clear")

        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        for line in lines:
            for text, style in line:
                self.output.insert("end", text, style or ())
            self.output.insert("end", "\n")
        self.output.configure(state="disabled")


def main():
    root = tk.Tk()
    TerminalApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
