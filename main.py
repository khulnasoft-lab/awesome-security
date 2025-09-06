import requests
import html
import re
import time
import random
import logging
import pandas as pd
import plotly.express as px
from datetime import datetime
from peewee import *

# -------------------- CONFIG --------------------
DB_FILE = "db/cve.sqlite"
README_FILE = "docs/README.md"
GITHUB_API_URL = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&page={}&per_page=100"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/{}"
RETRY_ATTEMPTS = 3
SLEEP_BETWEEN_REQUESTS = (3, 10)
CVE_REGEX = re.compile(r"[Cc][Vv][Ee][-_]\d{4}[-_]\d{4,7}")
GITHUB_PAGES = 3  # Number of GitHub pages to fetch per year

# -------------------- LOGGING --------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------- DATABASE --------------------
db = SqliteDatabase(DB_FILE)

class CVE_DB(Model):
    id = IntegerField(unique=True)
    full_name = CharField(max_length=1024)
    description = CharField(max_length=200)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)
    cve = CharField(max_length=64)
    base_score = FloatField(null=True)
    severity = CharField(max_length=20, null=True)
    attack_vector = CharField(max_length=20, null=True)

    class Meta:
        database = db

def initialize_db():
    db.connect()
    db.create_tables([CVE_DB], safe=True)

# -------------------- README --------------------
def initialize_readme():
    with open(README_FILE, 'w') as f:
        f.write("# GitHub CVE Monitor\n\n> Automatic CVE monitor with NVD integration\n\n")
        f.write("Last generated: {}\n\n".format(datetime.now()))
        f.write("| CVE | Name | Description | Date | CVSS | Severity | Attack Vector |\n")
        f.write("|---|---|---|---|---|---|---|\n")

def write_to_readme(new_contents):
    with open(README_FILE, 'a') as f:
        f.write(new_contents)

# -------------------- FETCH --------------------
def get_github_repos(year, page):
    """Fetch CVE repos from GitHub with exponential backoff retry."""
    base_delay = 2  # seconds
    for attempt in range(RETRY_ATTEMPTS):
        try:
            resp = requests.get(GITHUB_API_URL.format(year, page), timeout=15)
            resp.raise_for_status()
            return resp.json().get("items", [])
        except requests.RequestException as e:
            logging.warning(f"GitHub attempt {attempt+1} failed: {e}")
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logging.info(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)
    logging.error(f"Failed to fetch GitHub CVEs for year {year}, page {page}")
    return []

def get_nvd_cve(cve_id):
    """Fetch CVSS/NVD details for a CVE."""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            resp = requests.get(NVD_API_URL.format(cve_id), timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if metrics := data.get("result", {}).get("CVE_Items", []):
                metrics = metrics[0].get("impact", {})
                cvss = metrics.get("baseMetricV3", metrics.get("baseMetricV2", {}))
                score = cvss.get("cvssV3", {}).get("baseScore") or cvss.get("cvssV2", {}).get("baseScore")
                severity = cvss.get("cvssV3", {}).get("baseSeverity") or cvss.get("cvssV2", {}).get("severity")
                av = cvss.get("cvssV3", {}).get("attackVector") or cvss.get("cvssV2", {}).get("accessVector")
                return score, severity, av
            return None, None, None
        except requests.RequestException as e:
            logging.warning(f"NVD attempt {attempt+1} failed for {cve_id}: {e}")
            time.sleep(random.randint(1, 5))
    return None, None, None

# -------------------- PROCESS --------------------
def match_and_insert_cves(items):
    cve_list = []
    for item in items:
        id_ = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id_).exists():
            continue

        full_name = html.escape(item["full_name"])
        description = html.escape((item.get("description") or "no description").strip())
        url = item["html_url"]
        cve_match = CVE_REGEX.search(url + description)
        cve = cve_match.group().upper().replace('_', '-') if cve_match else None
        created_at = item["created_at"]

        base_score, severity, attack_vector = (None, None, None)
        if cve:
            base_score, severity, attack_vector = get_nvd_cve(cve)
            time.sleep(random.uniform(0.5, 2))  # NVD rate-limit protection

        CVE_DB.create(id=id_, full_name=full_name, description=description, url=url,
                      created_at=created_at, cve=cve or "CVE Not Found",
                      base_score=base_score, severity=severity, attack_vector=attack_vector)

        cve_list.append({
            "id": id_,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at,
            "cve": cve or "CVE Not Found",
            "base_score": base_score,
            "severity": severity,
            "attack_vector": attack_vector
        })
    return sorted(cve_list, key=lambda e: e["created_at"])

# -------------------- README --------------------
def generate_readme():
    df = pd.DataFrame(list(CVE_DB.select().dicts()))
    for _, row in df.iterrows():
        cve_link = f"https://www.cve.org/CVERecord?id={row['cve']}" if "CVE" in row['cve'] else row['url']
        write_to_readme(
            f"| [{row['cve']}]({cve_link}) | [{row['full_name']}]({row['url']}) | "
            f"{row['description'].replace('|','-')} | {row['created_at']} | "
            f"{row.get('base_score','-')} | {row.get('severity','-')} | {row.get('attack_vector','-')} |\n"
        )

    # CVSS Histogram
    if not df.empty:
        df_scores = df.dropna(subset=['base_score'])
        if not df_scores.empty:
            fig = px.histogram(df_scores, x="base_score", nbins=10, title="CVSS Score Distribution")
            try:
                fig.write_html("docs/cvss_distribution.html")
                logging.info("CVSS histogram saved to docs/cvss_distribution.html")
            except Exception as e:
                logging.error(f"Failed to save CVSS histogram to docs/cvss_distribution.html: {e}")
            fig.write_html("docs/cvss_distribution.html")
            logging.info("CVSS histogram saved to docs/cvss_distribution.html")

# -------------------- MAIN --------------------
def main():
    initialize_db()
    initialize_readme()
    current_year = datetime.now().year
    for year in range(current_year, 1999, -1):
        for page in range(1, GITHUB_PAGES + 1):
            items = get_github_repos(year, page)
            if not items:
                continue
            logging.info(f"Year {year}, page {page}: {len(items)} repos retrieved")
            match_and_insert_cves(items)
            time.sleep(random.randint(*SLEEP_BETWEEN_REQUESTS))

    generate_readme()
    logging.info("README with NVD/CVSS data generated successfully.")

if __name__ == "__main__":
    main()
