from functools import total_ordering
import requests
from peewee import *
from datetime import datetime
import html
import time
import random
import math
import re
import csv

db = SqliteDatabase("db/cve.sqlite")

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=200)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)
    cve = CharField(max_length=64)

    class Meta:
        database = db

db.connect()
db.create_tables([CVE_DB])

def init_file():
    newline = "# Github CVE Monitor\n\n> Automatic monitor github cve using Github Actions \n\n Last generated : {}\n\n| CVE | Name | Description | Date |\n|---|---|---|---|\n".format(datetime.now())
    with open('docs/README.md','w') as f:
        f.write(newline) 
    f.close()

def write_file(new_contents):
    with open('docs/README.md','a') as f:
        f.write(new_contents)
    f.close()

def get_info(year):
    try:
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&page=3&per_page=500".format(year)
        # API
        req = requests.get(api).json()
        items = req["items"]
        return items
    except Exception as e:
        print("An error occurred in the network request", e)
        return None


def db_match(items):
    r_list = []
    regex = r"[Cc][Vv][Ee][-_]\d{4}[-_]\d{4,7}"
    cve = ''
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0:
            continue
        full_name = html.escape(item["full_name"])
        description = item["description"]
        if description == "" or description == None:
            description = 'no description'
        else:
            description = html.escape(description.strip())
        url = item["html_url"]
### EXTRACT CVE 
        matches = re.finditer(regex, url, re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            cve = match.group()
        if not cve:
            matches = re.finditer(regex, description, re.MULTILINE)
            cve = "CVE Not Found"
            for matchNum, match in enumerate(matches, start=1):
                cve = match.group()
### 
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at,
            "cve": cve.replace('_','-')
        })
        CVE_DB.create(id=id,
                      full_name=full_name,
                      description=description,
                      url=url,
                      created_at=created_at,
                      cve=cve.upper().replace('_','-'))

    return sorted(r_list, key=lambda e: e.__getitem__('created_at'))

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
    
    # Write CVE information to README file in CSV format
    with open(README_FILE, 'a', newline='') as csvfile:
        fieldnames = ['CVE', 'Name', 'Description', 'Date']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for cve_info in CVE_DB.select().order_by(CVE_DB.cve.desc()):
            cve = cve_info.cve
            full_name = cve_info.full_name
            description = cve_info.description.replace('|', '-')
            publish_date = cve_info.created_at
            if cve.upper() == "CVE NOT FOUND":
                writer.writerow({'CVE': cve.upper(), 'Name': full_name, 'Description': description, 'Date': publish_date})
            else:
                writer.writerow({'CVE': cve.upper(), 'Name': full_name, 'Description': description, 'Date': publish_date})
    
    # TODO: Add code for statistics

if __name__ == "__main__":
    main()
