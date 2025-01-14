#!/usr/bin/env python3
##/var/ossec/framework/python/bin/python3 /home/wazuh-user/syscollector-report/src/sqlite_fim.py

import os
import sqlite3
import json

def check_db_access(db_path):
    return os.path.isfile(db_path) and os.access(db_path, os.R_OK)

def show_fim(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM file_entry")
        fim = cursor.fetchall()
        if fim:
            columns = [column[0] for column in cursor.description]  # Get column names
            data = [dict(zip(columns, row)) for row in fim]
            # Convert the data to JSON
            json_data = json.dumps(data, indent=4)
            # Print or save the JSON data
            print(json_data)
        else:
            print("No fim data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def main():
    db_path = os.path.expanduser("/var/ossec/queue/fim/db/fim.db")

    if check_db_access(db_path):
        show_fim(db_path)
    else:
        print("Database file is not accessible.")

if __name__ == "__main__":
    main()