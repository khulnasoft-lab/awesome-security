import requests
import html
import re
import time
import random
from datetime import datetime
from peewee import *

# Constants
DB_FILE = "db/cve.sqlite"
README_FILE = "docs/README.md"
API_URL = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&page=3&per_page=500"

# Database setup
db = SqliteDatabase(DB_FILE)

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=200)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)
    cve = CharField(max_length=64)

    class Meta:
        database = db

# Initialize database
def initialize_db():
    db.connect()
    db.create_tables([CVE_DB])

# Initialize README file
def initialize_readme():
    with open(README_FILE, 'w') as f:
        f.write("# Github CVE Monitor\n\n> Automatic monitor github cve using Github Actions\n\n")
        f.write("Last generated: {}\n\n".format(datetime.now()))
        f.write("| CVE | Name | Description | Date |\n|---|---|---|---|\n")

# Write to README file
def write_to_readme(new_contents):
    with open(README_FILE, 'a') as f:
        f.write(new_contents)

# Get CVE information from GitHub API
def get_cve_info(year):
    try:
        req = requests.get(API_URL.format(year)).json()
        return req.get("items", [])
    except Exception as e:
        print("An error occurred in the network request:", e)
        return []

# Match CVEs and insert into database
def match_and_insert_cves(items):
    regex = r"[Cc][Vv][Ee][-_]\d{4}[-_]\d{4,7}"
    cve_list = []
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0:
            continue
        full_name = html.escape(item["full_name"])
        description = html.escape(item.get("description", "no description").strip())
        url = item["html_url"]
        cve = re.search(regex, url + description).group() if re.search(regex, url + description) else "CVE Not Found"
        created_at = item["created_at"]
        cve_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at,
            "cve": cve.replace('_', '-')
        })
        CVE_DB.create(id=id, full_name=full_name, description=description, url=url, created_at=created_at, cve=cve.upper().replace('_', '-'))
    return sorted(cve_list, key=lambda e: e["created_at"])

# Main function
def main():
    initialize_db()
    initialize_readme()
    sorted_list = []
    current_year = datetime.now().year
    for year in range(current_year, 1999, -1):
        cve_info = get_cve_info(year)
        if not cve_info:
            continue
        print("Year {}: {} articles retrieved".format(year, len(cve_info)))
        sorted_cves = match_and_insert_cves(cve_info)
        if sorted_cves:
            print("Year {}: {} articles updated".format(year, len(sorted_cves)))
            sorted_list.extend(sorted_cves)
        time.sleep(random.randint(3, 15))
    
    # Write CVE information to README file
    for cve_info in CVE_DB.select().order_by(CVE_DB.cve.desc()):
        cve = cve_info.cve
        full_name = cve_info.full_name
        description = cve_info.description.replace('|', '-')
        publish_date = cve_info.created_at
        if cve.upper() == "CVE NOT FOUND":
            newline = "| {} | [{}]({}) | {} | {} |\n".format(cve.upper(), full_name, cve_info.url, description, publish_date)
        else:
            newline = "| [{}]({}) | [{}]({}) | {} | {} |\n".format(cve.upper(), "https://www.cve.org/CVERecord?id=" + cve.upper(), full_name, cve_info.url, description, publish_date)
        write_to_readme(newline)

    # TODO: Add code for statistics

if __name__ == "__main__":
    main()
