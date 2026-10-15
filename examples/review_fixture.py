"""Deliberately unsafe teaching fixture. Scan it; do not run or deploy it."""
import subprocess

def search(cursor, name):
    return cursor.execute(f"SELECT * FROM people WHERE name = '{name}'")

def convert(filename):
    subprocess.run("convert " + filename, shell=True)

def safe_search(cursor, name):
    return cursor.execute("SELECT * FROM people WHERE name = ?", (name,))
