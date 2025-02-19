#!/usr/bin/env python3
##/var/ossec/framework/python/bin/python3 /home/wazuh-user/syscollector-report/src/sqlite_osinfo.py

import os
import sqlite3
import glob
import os

def check_db_access(db_path):
    return os.path.isfile(db_path) and os.access(db_path, os.R_OK)

def show_osinfo(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_osinfo")
        osinfo = cursor.fetchall()
        if osinfo:
            print("Data in the osinfo database:")
            for row in osinfo:
                print(row)
        else:
            print("No osinfo data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_hotfixes(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_hotfixes")
        hotfixes = cursor.fetchall()
        if hotfixes:
            print("Data in the hotfixes database:")
            for row in hotfixes:
                print(row)
        else:
            print("No hotfixes data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_hwinfo(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_hwinfo")
        hwinfo = cursor.fetchall()
        if hwinfo:
            print("Data in the hwinfo database:")
            for row in hwinfo:
                print(row)
        else:
            print("No hwinfo data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_netaddr(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_netaddr")
        netaddr = cursor.fetchall()
        if netaddr:
            print("Data in the netaddr database:")
            for row in netaddr:
                print(row)
        else:
            print("No netaddr data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_netiface(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_netiface")
        netiface = cursor.fetchall()
        if netiface:
            print("Data in the netiface database:")
            for row in netiface:
                print(row)
        else:
            print("No netiface data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_netproto(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_netproto")
        netproto = cursor.fetchall()
        if netproto:
            print("Data in the netproto database:")
            for row in netproto:
                print(row)
        else:
            print("No netproto data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_ports(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_ports")
        ports = cursor.fetchall()
        if ports:
            print("Data in the ports database:")
            for row in ports:
                print(row)
        else:
            print("No ports data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_processes(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_processes")
        processes = cursor.fetchall()
        if processes:
            print("Data in the processes database:")
            for row in processes:
                print(row)
        else:
            print("No processes data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def show_programs(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sys_programs")
        programs = cursor.fetchall()
        if programs:
            print("Data in the programs database:")
            for row in programs:
                print(row)
        else:
            print("No programs data found in the database.")
        conn.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

def main():
    #db_path = os.path.expanduser("~/410.db")
    #db_path = os.path.expanduser("/var/ossec/queue/syscollector/db/local.db")
    #db_path = os.path.expanduser("/var/ossec/queue/db/002.db")
    # Database path
    dir_path = os.path.expanduser("/var/ossec/queue/db/")

    #Search for filenames that match the pattern [0-9][0-9][0-9].db
    files = glob.glob(os.path.join(dir_path, '[0-9][0-9][0-9].db'))
    for db_path in files:
        if check_db_access(db_path):
            print(f"Start procesing: {db_path}")
            print("Database file is accessible.")
            show_osinfo(db_path)
            show_hotfixes(db_path)
            show_hwinfo(db_path)
            show_netaddr(db_path)
            show_netiface(db_path)
            show_netproto(db_path)
            show_ports(db_path)
            show_processes(db_path)
            show_programs(db_path)
            print(f"End procesing: {db_path}")
        else:
            print("Database file is not accessible.")

if __name__ == "__main__":
    main()