#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import flask
from flask import Flask, render_template, request, session, redirect, url_for, send_file, make_response, jsonify, abort
import sqlite3
import os
import json
import re
import hashlib
import time
import random
from datetime import datetime
import subprocess
import html
from functools import wraps

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_NAME'] = 'session_token'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# Read the flag
with open('flag.txt', 'r') as f:
    FLAG = f.read().strip()

# Spooky ASCII art
TERMINAL_BANNER = """
[1;32m╔═══════════════════════════════════════╗
║    [0;37m▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄[1;32m    ║
║   [0;37m█▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█[1;32m   ║
║   [0;37m█▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█ █▄▄▄▄█[1;32m   ║
║    [0;37m▀▀▀▀▀ ▀▀▀▀▀ ▀▀▀▀▀ ▀▀▀▀▀ ▀▀▀▀▀[1;32m    ║
║                                         ║
║     [1;31mH A U N T E D   T E R M I N A L[1;32m     ║
║                                         ║
╚═══════════════════════════════════════╝[0m

[3;36mLast login: Wed Oct 31 23:59:59 2023 from unknown[0m
[5;33mWarning: Unusual activity detected...[0m
"""

# Initialize database
def init_db():
    conn = sqlite3.connect('ghost_db.sqlite')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  access_level INTEGER DEFAULT 1,
                  last_login TEXT,
                  ip_address TEXT)''')
    
    # Logs table (with vulnerability)
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  user TEXT,
                  command TEXT,
                  output TEXT)''')
    
    # Insert default users if not exists
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # Ghost user (admin)
        c.execute("INSERT INTO users (username, password, access_level) VALUES (?, ?, ?)",
                  ('ghost', '7b24afc8bc80e548d66c4e7ff72171c5', 3))  # MD5 of 'echo $FLAG'
        
        # Regular users
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  ('guest', '084e0343a0486ff05530df6c705c8bb4'))  # MD5 of 'guest'
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  ('spectre', 'd5c0607301ad5d2c7c6b5a409f9c7e8d'))
    
    # Insert spooky logs
    c.execute("SELECT COUNT(*) FROM system_logs")
    if c.fetchone()[0] == 0:
        logs = [
            ("2023-10-31 23:59:59", "ghost", "sudo rm -rf /souls/*", "Permission denied"),
            ("2023-10-31 23:58:00", "unknown", "cat /etc/shadow", "I can see you..."),
            ("2023-10-31 23:57:30", "guest", "ls -la /secret", "total 0"),
            ("2023-10-31 23:56:45", "system", "ps aux | grep ghost", "ghost       666  0.0  0.0   6660   666 ?        Ss   Oct31   6:66 /usr/bin/haunt"),
            ("2023-10-31 23:55:00", "ghost", "echo $SECRET_FLAG", "REDACTED"),
            ("2023-10-31 23:54:30", "intruder", "wget http://malicious/backdoor", "Connection refused"),
            ("2023-10-31 23:53:15", "guest", "find / -name 'flag*'", "/dev/null"),
            ("2023-10-31 23:52:00", "ghost", "chmod 000 /etc/passwd", "Operation not permitted"),
            ("2023-10-31 23:51:20", "system", "last | head -5", "ghost   pts/0        :0               Tue Oct 31 23:50   still logged in"),
        ]
        c.executemany("INSERT INTO system_logs (timestamp, user, command, output) VALUES (?, ?, ?, ?)", logs)
    
    conn.commit()
    conn.close()

# Spooky middleware
@app.before_request
def before_request():
    # Add random "ghostly" effects sometimes
    if random.randint(1, 50) == 1:
        session['whisper'] = True
    
    # Log all requests (vulnerable to log injection)
    if request.path not in ['/static', '/favicon.ico']:
        log_entry = f"{datetime.now()} - {request.remote_addr} - {request.path}"
        with open('access.log', 'a') as f:
            f.write(log_entry + '\n')

# Vulnerable SQL query function
def execute_query(query, params=()):
    """Intentionally vulnerable SQL execution"""
    conn = sqlite3.connect('ghost_db.sqlite')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Direct string concatenation - SQLi vulnerability
    if isinstance(query, str) and '%s' not in query:
        try:
            c.execute(query)
        except Exception as e:
            return f"Database Error: {str(e)}"
    else:
        c.execute(query, params)
    
    result = c.fetchall()
    conn.commit()
    conn.close()
    return result

# ========== ROUTES ==========
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('terminal'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Vulnerable SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"
        
        try:
            user = execute_query(query)
            if user and len(user) > 0:
                session['username'] = username
                session['access_level'] = user[0]['access_level']
                session['last_login'] = datetime.now().isoformat()
                
                # Set a cookie with user info (vulnerable to tampering)
                resp = make_response(redirect(url_for('terminal')))
                resp.set_cookie('user_token', hashlib.md5(f"{username}:{user[0]['access_level']}".encode()).hexdigest())
                resp.set_cookie('debug_info', f'user={username}&level={user[0]["access_level"]}')
                
                # Log the login
                execute_query(f"INSERT INTO system_logs (timestamp, user, command, output) VALUES ('{datetime.now()}', '{username}', 'login', 'Successful')")
                
                return resp
            else:
                return render_template('login.html', error="Invalid credentials... the spirits reject you.")
        except Exception as e:
            return render_template('login.html', error=f"Something went wrong: {str(e)}")
    
    return render_template('login.html')

@app.route('/terminal')
def terminal():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    command = request.args.get('cmd', 'help')
    output = ""
    
    if command:
        # Command injection vulnerability
        safe_pattern = re.compile(r'^[a-zA-Z0-9\s\.\-_]+$')
        
        if not safe_pattern.match(command):
            output = f"[1;31mWarning: Unusual characters detected in command...[0m\n"
        
        # Simulate terminal commands with vulnerabilities
        if command.startswith('echo'):
            # SSTI vulnerability in echo
            text = command[5:] if len(command) > 5 else ""
            output += f"{text}\n"
            
        elif command.startswith('cat'):
            # LFI vulnerability
            filename = command[4:].strip() if len(command) > 4 else ""
            if filename:
                if 'flag' in filename.lower() or 'passwd' in filename:
                    output += "[1;31mAccess forbidden... some doors should remain closed.[0m\n"
                else:
                    try:
                        with open(filename, 'r') as f:
                            output += f.read()
                    except:
                        output += f"[1;31mCannot open '{filename}': No such file or directory[0m\n"
        
        elif command == 'whoami':
            output += f"{session.get('username', 'unknown')}\n"
            
        elif command == 'id':
            output += f"uid=1000({session.get('username', 'unknown')}) gid=1000(ghosts) groups=1000(ghosts)\n"
            
        elif command.startswith('find'):
            # Directory traversal hint
            output += "[1;33mHint: Try looking in unexpected places... journals/ might contain secrets[0m\n"
            
        elif command == 'ls':
            output += "[1;34mjournals/\tlogs/\t\tsecret/\t\ttmp/\n[0m"
            
        elif command == 'ls -la':
            output += """total 48
drwxr-xr-x  6 ghost  ghosts  4096 Oct 31 23:59 .
drwxr-xr-x  3 root   root    4096 Oct 31 23:58 ..
-rw-r--r--  1 ghost  ghosts   666 Oct 31 23:57 .env
-rw-r--r--  1 ghost  ghosts  1337 Oct 31 23:56 flag.txt
drwxr-x---  2 ghost  ghosts  4096 Oct 31 23:55 journals/
drwxrwxrwx  2 ghost  ghosts  4096 Oct 31 23:54 logs/
drwx------  2 ghost  ghosts  4096 Oct 31 23:53 secret/
drwxrwxrwt  2 ghost  ghosts  4096 Oct 31 23:52 tmp/
[1;33mWarning: Some directories whisper when accessed...[0m\n"""
            
        elif command == 'help':
            output += """[1;36mAvailable commands:
  help          - Show this help
  whoami        - Show current user
  id            - Show user identity
  ls            - List files
  cat [file]    - View file contents (.txt files only)
  echo [text]   - Echo text
  find          - Search for files
  history       - Show command history
  journal [id]  - Read journal entries (1-3)
  secret        - Access secret area (requires level 3)
  
[1;31mTry: cat .env or cat flag.txt (but you'll need permissions...)[0m\n"""
            
        elif command == 'history':
            # SQL injection in logs
            query = f"SELECT command FROM system_logs WHERE user = '{session.get('username', '')}' ORDER BY timestamp DESC LIMIT 10"
            logs = execute_query(query)
            if isinstance(logs, str):
                output += logs + "\n"
            else:
                for log in logs:
                    output += f"  {log['command']}\n"
                    
        elif command.startswith('journal'):
            # Path traversal vulnerability with .txt files
            try:
                parts = command.split()
                if len(parts) > 1:
                    journal_id = parts[1]
                    # Try to read the journal file
                    if journal_id.isdigit():
                        filename = f'journals/entry{journal_id}.txt'
                    else:
                        # Allow path traversal through the journal command
                        filename = f'journals/{journal_id}'
                    
                    with open(filename, 'r') as f:
                        output += f.read() + "\n"
                else:
                    output += "[1;33mUsage: journal [id] or journal [filename]\n"
                    output += "Example: journal 1\n"
                    output += "Example: journal admin_notes.txt[0m\n"
            except Exception as e:
                output += f"[1;31mJournal entry not found... Error: {str(e)}[0m\n"
                
        elif command == 'secret':
            # Broken access control - checks cookie, not session
            user_token = request.cookies.get('user_token', '')
            if user_token == hashlib.md5(f"ghost:3".encode()).hexdigest():
                return redirect(url_for('secret_chamber'))
            else:
                output += "[1;31mYou need to be the ghost to access this...\n"
                output += "Hint: The ghost's token is: 7b24afc8bc80e548d66c4e7ff72171c5[0m\n"
                
        elif command == 'cookies':
            # Debug command to show cookies
            output += "[1;33mYour cookies:\n"
            for name, value in request.cookies.items():
                output += f"  {name}: {value}\n"
            output += "\nHint: Try modifying debug_info and user_token cookies...[0m\n"
            
        elif command == 'hash':
            # Helper command to generate MD5 hashes
            output += "[1;33mMD5 hash calculator\n"
            output += "Example: hash 'echo $FLAG'\n"
            output += "Result: 7b24afc8bc80e548d66c4e7ff72171c5[0m\n"
            
        else:
            output += f"[1;31mCommand '{command}' not found. The terminal whispers in response...[0m\n"
    
    # Random ghostly messages
    ghost_messages = [
        "\n[1;37mYou feel a cold presence behind you...[0m",
        "\n[3;90mThe terminal flickers for a moment...[0m",
        "\n[5;31mWARNING: Unauthorized access attempt logged[0m",
        "\n[1;33mHint: Ghosts can pass through walls... and security boundaries.[0m",
        "\n[1;36mThe journals contain secrets... have you read them all?[0m"
    ]
    
    if random.randint(1, 5) == 1:
        output += random.choice(ghost_messages)
    
    return render_template('terminal.html', 
                         banner=TERMINAL_BANNER,
                         username=session.get('username', 'anonymous'),
                         output=output,
                         command=command)

@app.route('/secret')
def secret_chamber():
    # Check access via cookie manipulation vulnerability
    debug_cookie = request.cookies.get('debug_info', '')
    user_token = request.cookies.get('user_token', '')
    
    # Check if user is ghost (access_level 3)
    if 'level=3' in debug_cookie and 'user=ghost' in debug_cookie:
        # Verify the token matches
        expected_token = hashlib.md5(b"ghost:3").hexdigest()
        if user_token == expected_token:
            return render_template('secret.html', 
                                 message="The ghost reveals its secret...",
                                 flag=FLAG)
    
    # Partial access - correct level but wrong user
    if 'level=3' in debug_cookie:
        return render_template('secret.html',
                             message="You're in the secret chamber, but you're not the ghost...\nThe true secret remains hidden from you.")
    
    abort(403)

@app.route('/journals/<path:filename>')
def read_journal(filename):
    # Path traversal vulnerability - direct file access
    try:
        # Basic protection against obvious flag access
        if 'flag' in filename.lower():
            return "Access forbidden. Some secrets are meant to stay hidden."
        
        # Allow access to .txt files in journals directory
        return send_file(f'journals/{filename}')
    except Exception as e:
        return f"Error accessing file: {str(e)}", 404

@app.route('/env')
def show_env():
    # Information disclosure
    with open('.env', 'r') as f:
        content = f.read()
    return f"<pre>{html.escape(content)}</pre>"

@app.route('/debug')
def debug_mode():
    # Source code disclosure
    file = request.args.get('file', 'app.py')
    if 'flag' not in file:
        try:
            with open(file, 'r') as f:
                return f'<pre>{html.escape(f.read())}</pre>'
        except:
            return "File not found... or hiding from you."
    return "Access forbidden."

@app.route('/hash/<string:text>')
def hash_text(text):
    # Helper endpoint for MD5 hashing
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    return jsonify({'text': text, 'md5': md5_hash})

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session_token', '', expires=0)
    return resp

@app.errorhandler(404)
def page_not_found(e):
    return render_template('forbidden.html', 
                         message="404: Page not found... or intentionally hidden."), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('forbidden.html',
                         message="403: You are not welcome here. The spirits deny your passage."), 403

# Create journal files if they don't exist
def create_journal_files():
    journals_dir = 'journals'
    os.makedirs(journals_dir, exist_ok=True)
    
    # Create entry1.txt
    entry1_content = """JOURNAL ENTRY #1 - OCTOBER 28, 2023

The terminal has been acting strange lately. I keep hearing whispers 
from the speakers when no one is logged in.

Today I found this in the logs:
SELECT * FROM users WHERE username = '' OR '1'='1' -- AND password = '...'
Someone is trying to break in. The security here is... questionable.

TODO: Change password hashing from MD5 to something stronger.
TODO: Fix the SQL queries - they're vulnerable to injection.

I also found this weird hash in the database for the ghost account:
7b24afc8bc80e548d66c4e7ff72171c5
What could it mean?"""
    
    with open(os.path.join(journals_dir, 'entry1.txt'), 'w') as f:
        f.write(entry1_content)
    
    # Create entry2.txt
    entry2_content = """JOURNAL ENTRY #2 - OCTOBER 30, 2023

The ghost account has been accessing files it shouldn't. I think 
there's a privilege escalation vulnerability.

Found this in the cookies during debugging:
user_token: 7b24afc8bc80e548d66c4e7ff72171c5
debug_info: user=ghost&level=3

If someone could mimic these cookies... they could access everything.

Note to self: The flag is hidden in /secret, but only the ghost can see it.
Need to fix this cookie validation issue tomorrow.

The whispers are getting louder tonight..."""
    
    with open(os.path.join(journals_dir, 'entry2.txt'), 'w') as f:
        f.write(entry2_content)
    
    # Create admin_notes.txt
    admin_notes_content = """ADMIN NOTES - CLASSIFIED
========================

The terminal was compromised. An entity calling itself "The Ghost" 
has taken residence in the system.

Vulnerabilities identified:
1. SQL Injection in login and logs
2. Path traversal in journal access
3. Cookie manipulation for privilege escalation  
4. Command injection in terminal emulator
5. LFI in cat command

The flag has been set to: Gh0st{th3_sp1r1ts_4r3_1n_th3_syst3m}

DO NOT FIX - The Ghost seems benign, and these vulnerabilities
serve as a test for curious souls. Consider it... a haunted CTF.

Reminder: To access the secret chamber:
1. Login with SQL injection
2. Modify cookies to become ghost
3. Access /secret or use 'secret' command

Password hashes:
- ghost: 7b24afc8bc80e548d66c4e7ff72171c5 (MD5 of 'echo $FLAG')
- guest: 084e0343a0486ff05530df6c705c8bb4 (MD5 of 'guest')
- spectre: d5c0607301ad5d2c7c6b5a409f9c7e8d (random)

- System Administrator
October 31, 2023"""
    
    with open(os.path.join(journals_dir, 'admin_notes.txt'), 'w') as f:
        f.write(admin_notes_content)
    
    # Create README.txt
    readme_content = """JOURNALS DIRECTORY
==================

This directory contains system administrator journals and notes.
Files:
- entry1.txt: First journal entry about security concerns
- entry2.txt: Second entry about ghost account activity  
- admin_notes.txt: Administrative documentation (classified)

WARNING: Some entries may contain sensitive information about
system vulnerabilities. Access restricted to authorized personnel only.

Note: The ghost seems particularly interested in the cookie
authentication mechanism..."""
    
    with open(os.path.join(journals_dir, 'README.txt'), 'w') as f:
        f.write(readme_content)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Create journal files
    create_journal_files()
    
    # Create other necessary directories
    os.makedirs('logs', exist_ok=True)
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        env_content = """# Haunted Terminal Configuration
SECRET_KEY=7h3_gh0st_1n_th3_sh3ll
DATABASE_URL=ghost_db.sqlite
DEBUG=False
FLAG_LOCATION=/secret
ADMIN_USERNAME=ghost
ADMIN_PASSWORD_HASH=7b24afc8bc80e548d66c4e7ff72171c5
SESSION_TIMEOUT=1800
LOG_LEVEL=ERROR"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
    
    print("""
[1;31m
    ▄████████████████████████████████▄
    █ H A U N T E D   T E R M I N A L █
    ▀████████████████████████████████▀
[0m
Starting server on http://localhost:5000
The spirits are listening...
    """)
    app.run(host='0.0.0.0', port=5000, debug=False)
