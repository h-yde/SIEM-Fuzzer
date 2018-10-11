import os
import sqlite3
from uuid import uuid4

def createDatabase():
    admin_username = raw_input("[i] Please select administrator username: ")
    admin_password = raw_input("[i] Please enter your desired password: ")
    admin_password_confirm = raw_input("[i] Please confirm desired password: ")
    if admin_password == admin_password_confirm:
        # SQLite Database
        sqlite_connection = sqlite3.connect("sqlite.db")
        c = sqlite_connection.cursor()
        c.execute("CREATE TABLE secret_key (uuid text)")
        c.execute("CREATE TABLE fuzzer_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username text,password text, is_admin INTEGER, uuid text)")
        c.execute("CREATE TABLE fuzzer_payloads (id INTEGER PRIMARY KEY AUTOINCREMENT, payload_category INTEGER, injection_key text, b64json_array text)")
        #c.execute("CREATE TABLE fuzzer_pingbacks (username text,password text)")
        c.execute("INSERT INTO fuzzer_users VALUES (:id, :username, :password, :is_admin, :uuid)", {'id': None, 'username':admin_username, 'password':admin_password, 'is_admin':1, 'uuid':str(uuid4())[:5] })
        c.execute("INSERT INTO secret_key VALUES (:uuid)", {'uuid':str(uuid4())})
        sqlite_connection.commit()
        sqlite_connection.close()
        print("[+] Database Created!")
    else:
        print("[!] Passwords do not match!")
print("[+] SIEM Fuzzer Admin Setup")
if 'sqlite.db' in os.listdir('.'):
    print("[!] Warning! Running this script will delete your old database.")
    delete_answer = raw_input("[i] Are you sure you would you like to continue (Y/N): ")
    if delete_answer.lower() == "y":
        os.remove("sqlite.db")
        print("[-] Removing old database...")
        createDatabase()
    else:
        print("[+] Exiting Setup...")
else:
    createDatabase()