# File for providers of data (API's) used in this application

import csv
import datetime
import json
# import logging
import os
# import sys
# import time
from pathlib import Path

import pandas as pd
import requests
import yaml
from bs4 import BeautifulSoup as BS

from .formatters import clean_multiline_string


DEBUG = False
APP_DIR = Path(__file__).resolve(strict=True).parent.parent
# CONFIG_DIR = APP_DIR / "config"
SAVE_DIR = APP_DIR / "datasets"
# Set initial defaults
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"


class CVERetrieverNVD(object):
    """ A class object to facilitate retrieving CVE data from NVD API, process and clean it,
        filter it based on user preference settings, and return a list of the filtered results
        for further use by a separate script file.

        API Reference: https://nvd.nist.gov/developers/vulnerabilities

        NOTE: A CVE result record will contain the following dictionary keys:
        "CVE_ID": cve_id,
        "Description": cve_description,
        "CVSSv3_Score": cvssv3_score,
        "CVSSv3_Severity": cvssv3_severity,
        "CVSSv3_Exploitability": cvssv3_exploitability,
        "CVSSv3_Impact": cvssv3_impact,
        "Published": published,
        "Last_Modified": last_modified,
        "Vuln_Status": vuln_status,
        "CWE": cwe,                                 # List of CWE's
        "Exploit_References": exploit_references,   # List of exploit-categorized refs
        "Normal_References": normal_references,     # List of normal-categorized refs
    """
    def __init__(self, testing=False):
        global APP_DIR, SAVE_DIR, DEBUG

        # During local dev testing, if True, this will skip writing timestamps to json file
        # so that we can run the script repeatedly and not update any timestamps
        # that will be used by the GitHub repo during scheduled executions.
        self.testing = testing

        # NOTE: NVD API rate limit w/o an API key: 5 requests in a rolling 30-second window (with key: 50 in 30s)
        self.base_url_nvd = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        self.keywords_config_path = APP_DIR / 'config' / 'botpeas.yaml'
        self.cve_settings_file = APP_DIR / 'config' / 'botpeas.json'

        # MITRE Exploit-DB Mapping - Set defaults, interval later read from config
        self.mitre_exploit_file = SAVE_DIR / 'mitre_exploit_map.csv'
        self.mitre_interval = 10
        self.last_mitre_retrieval = datetime.datetime.now() - datetime.timedelta(days=self.mitre_interval)

        # More defaults -- user preferences are later read from config
        self.search_scope = 'all_keywords'          # can be one of: "products", "all_keywords", "all_cves"
        self.include_high_severity = True           # Include High Severity CVE's regardless of keywords
        self.high_severity_threshold = 8.0          # Min CVSS score threshold for "high severity" scope
        self.enable_score_filtering = False         # Enable min. score for matching keywords also
        self.min_score_threshold = 6.0              # Min. score threshold for inclusion in results

        self.cve_new_dataset = []
        self.product_keywords = set()
        self.product_keywords_i = set()
        self.description_keywords = set()
        self.description_keywords_i = set()
        self.excluded_keywords = set()
        self.last_new_cve = datetime.datetime.now() - datetime.timedelta(days=1)
        self.last_modified_cve = datetime.datetime.now() - datetime.timedelta(days=1)

        self.time_format = "%Y-%m-%dT%H:%M:%S"

        if not os.path.exists(SAVE_DIR):
            os.makedirs(SAVE_DIR)

        # NOTE: param "hasKev" is present in CVE's that appear in CISA's Known Exploited Vulns catalog
        self.api_data_params = ['cveId', 'cvssV3Severity', 'cvssV2Severity', 'cvssV3Metrics',
            'cweId', 'hasKev', 'lastModStartDate', 'lastModEndDate', 'pubStartDate', 'pubEndDate',
            'resultsPerPage', 'startIndex', 'sourceIdentifier',
        ]
        self.load_cve_settings_file()
        self.load_keywords()
        return

    def load_keywords(self):
        with open(self.keywords_config_path, 'r') as yaml_file:
            keywords_config = yaml.safe_load(yaml_file)
            try:
                self.search_scope = keywords_config["SEARCH_SCOPE"]
                self.include_high_severity = keywords_config["INCLUDE_HIGH_SEVERITY"]
                self.high_severity_threshold = float(keywords_config["HIGH_SEVERITY_THRESHOLD"])
                self.enable_score_filtering = keywords_config['ENABLE_SCORE_FILTERING']
                self.min_score_threshold = keywords_config['MIN_SCORE_THRESHOLD']
                self.mitre_interval = keywords_config['MITRE_INTERVAL']
            except KeyError:
                print("[!] Your botpeas.yaml config file is missing new feature preference parameters. Using defaults for now which are defined in this class' (CVERetrieverNVD()) __init__() method")
                pass

            # NOTE: These all load as python list type objects
            self.product_keywords = keywords_config["PRODUCT_KEYWORDS"]
            self.product_keywords_i = keywords_config["PRODUCT_KEYWORDS_I"]
            self.description_keywords = keywords_config["DESCRIPTION_KEYWORDS"]
            self.description_keywords_i = keywords_config["DESCRIPTION_KEYWORDS_I"]
            self.excluded_keywords = keywords_config["EXCLUDED_KEYWORDS"]

            # NOTE: %3A is the url-encoded form of a colon ":"
            # Must also add it to the front because join() doesn't do the very front
            self.gitdork_excluded_repos_string = "+-repo:"
            self.gitdork_excluded_repos_string += "+-repo:".join([x for x in keywords_config["GITDORK_REPO_EXCLUSIONS"]])
            self.gitdork_excluded_repos_string += "+NOT is:fork"

        print("[*] Loaded config settings, search & exclusion keywords")

        # Load MITRE Exploit-DB Mapping Data
        self.download_exploit_mapping()
        self.exploit_map = []
        fieldnames = ["ExploitId", "CveId"]     # The original headers of the MITRE Exploit map file
        with open(self.mitre_exploit_file, 'r') as mitre_file:
            rdr = csv.DictReader(mitre_file)
            for row in rdr:
                # Creating a list of dicts we'll use later to see if an Exploit is listed for a CVE in our results
                self.exploit_map.append({'CVE_ID': row['CveId'], 'ExploitDB_ID': row['ExploitId']})
            print("[*] MITRE Exploit-DB ID Mapping has been loaded")
        return

    def load_cve_settings_file(self):
        if not os.path.exists(self.cve_settings_file):
            print("[!] Timestamp tracker botpeas.json file doesn't exist yet at {}".format(self.cve_settings_file))
            return
        try:
            with open(self.cve_settings_file, 'r') as json_file:
                self.cve_data_fromfile = json.load(json_file)
                self.last_new_cve = datetime.datetime.strptime(self.cve_data_fromfile["LAST_NEW_CVE"],
                                                               self.time_format)
                self.last_modified_cve = datetime.datetime.strptime(self.cve_data_fromfile["LAST_MODIFIED_CVE"],
                                                                    self.time_format)
                try:
                    # Tracking for periodic download of latest MITRE exploit-db mapping data
                    self.last_mitre_retrieval = datetime.datetime.strptime(self.cve_data_fromfile['LAST_MITRE_RETRIEVAL'], self.time_format)
                    if DEBUG: print("[DBG] Date timestamps all loaded from settings json file")
                except Exception as e:
                    # In case this is run but key is not yet in the file
                    if DEBUG: print("[DBG] Failed to load LAST_MITRE_RETRIEVAL from config file, defaulting to 5 days")
                    pass

        except Exception as e:
            print("[*] Error opening CVE Data JSON file, keeping default timestamps for search")
            pass
        return

    def update_cve_settings_file(self):
        """ Save this cycle's collection metadata to json file for next run. """

        if self.testing:
            print("[*] Testing mode is enabled, skipping settings file update")
            return

        if isinstance(self.last_mitre_retrieval, datetime.datetime):
            self.last_mitre_retrieval = self.last_mitre_retrieval.strftime(self.time_format)

        with open(self.cve_settings_file, 'w') as json_file:
            # Update our timestamp values with the updated timestamp created via self._build_query()
            json.dump({
                "LAST_NEW_CVE": self.updated_cve_timestamp,
                "LAST_MODIFIED_CVE": self.updated_cve_timestamp,
                "LAST_MITRE_RETRIEVAL": self.last_mitre_retrieval
            }, json_file, default=str)
        return

    def _build_query(self):
        # Query syntax for a typical grab of latest CVE's from NVD API 2.0
        now = datetime.datetime.now(datetime.timezone.utc)
        self.updated_cve_timestamp = now.strftime(self.time_format)
        self.last_new_cve = self.last_new_cve.strftime(self.time_format)
        self.last_modified_cve = self.last_modified_cve.strftime(self.time_format)

        #q = f"{self.base_url_nvd}?lastModStartDate={self.last_modified_cve}&lastModEndDate={self.updated_cve_timestamp}"
        q = f"{self.base_url_nvd}?pubStartDate={self.last_new_cve}&pubEndDate={self.updated_cve_timestamp}"
        if DEBUG: print(f"[DBG] Query URL we are using: {q}")
        return q

    def get_new_cves(self):
        """ Get latest CVE's from NVD's API service and store into dict. """
        full_url = self._build_query()
        print(f"[!] Fetching CVE data from URL: {full_url}")
        response = requests.get(full_url)
        # NVD recommends sleeping 6 secs between requests, but
        # we're only making 1 request, so no worries
        #time.sleep(6)
        if response.status_code != 200:
            print(f"[!] Error contacting NVD API for CVEs - response code: {response.status_code}")
            return

        nvd_json = json.loads(response.text)
        if DEBUG: print("[DBG] API json response has been loaded into a json object")

        results_total = nvd_json["totalResults"]
        print(f"[*] {results_total} CVE's pulled from NVD for processing, please wait...")
        for v in nvd_json["vulnerabilities"]:
            if DEBUG: print(f"\n[DBG] CVE Raw record: {v=}")
            # Start with all values empty on each iteration
            cve_description = ''
            cvssv3_score = ''
            cvssv3_severity = ''
            cvssv3_exploitability = ''
            cvssv3_impact = ''
            published = ''
            last_modified = ''
            vuln_status = ''
            cwe = []

            cve_id = v["cve"]['id']
            try:
                # Get CVE description and clean multi-line string
                cve_description = v['cve']['descriptions'][0]['value']
                # cve_description = cve_description.rstrip()
                cve_description = clean_multiline_string(cve_description)
            except KeyError:
                print("[DBG] KeyError with cve_description, raw data: {}".format(v['cve']['descriptions']))
            try:
                cvssv3_score = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                cvssv3_severity = v['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                cvssv3_exploitability = v['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
                cvssv3_impact = v['cve']['metrics']['cvssMetricV31'][0]['impactScore']
            except KeyError:
                pass

            published = v['cve']['published']
            last_modified = v['cve']['lastModified']
            vuln_status = v['cve']['vulnStatus']

            try:
                for entry in v['cve']['weaknesses'][0]['description']:
                    if entry['lang'] == 'en':
                        if entry['value'] == "NVD-CWE-noinfo":
                            continue
                        else:
                            cwe.append(entry['value'])
            except KeyError:
                # This CVE has no defined CWE's
                pass

            # -- Fine tune our references --
            exploit_references = []
            normal_references = []
            try:
                for entry in v['cve']['references']:
                    # Scrutinize what types of references we wish to include
                    if entry.get('tags') is not None:
                        if DEBUG:
                            print("[DBG] References raw tags: {}".format(entry['tags']))
                        if "Exploit" in entry['tags']:
                            exploit_references.append(entry['url'])
                        #if "Advisory" in entry['tags'] or "Patch" in entry['tags']:
                        if any(w in ["Third Party Advisory", "Vendor Advisory"] for w in entry['tags']):
                            normal_references.append(entry['url'])
                    else:
                        # Many of the CVE's do not have tags for the references, call them normal
                        normal_references.append(entry['url'])
            except KeyError:
                if DEBUG: print("[DBG] KeyError searching references - {}".format(entry))
                pass

            record = {
                "CVE_ID": cve_id,
                "Description": cve_description,
                "CVSSv3_Score": cvssv3_score,
                "CVSSv3_Severity": cvssv3_severity,
                "CVSSv3_Exploitability": cvssv3_exploitability,
                "CVSSv3_Impact": cvssv3_impact,
                "Published": published,
                "Last_Modified": last_modified,
                "Vuln_Status": vuln_status,
                "CWE": cwe,                                 # List of CWE's
                "Exploit_References": exploit_references,   # List of exploit categorized refs
                "Normal_References": normal_references,     # List of normal refs
            }
            self.cve_new_dataset.append(record)
            if DEBUG: print("[DBG] CVE entry appended to dataset: {}".format(record))

        # With new dataset, run it through filtering function
        # TODO: Would be more efficient if we could filter out CVE's before fully cleaning all data
        self.filter_cves()
        self.check_cve_has_exploit()
        self.update_cve_settings_file()
        return self.cve_new_dataset


    def filter_cves(self):
        filtered_cves = []
        for item in self.cve_new_dataset:
            # Which method(s) are we filtering by
            if self.enable_score_filtering:
                if not item.get('CVSSv3_Score'):
                    # Score filtering is enabled, but this one doesn't have a score
                    # item['CVSSv3_Score'] = "TBD"
                    print("[INFO] Skipping CVE with no CVSS Score; too noisy")
                    continue
                elif not self._cvss_score_at_above(item['CVE_ID'], item['CVSSv3_Score'], self.min_score_threshold):
                    # If score filtering is enabled, and CVE is below threshold, skip it altogether
                    print(f"[INFO] Filtering out CVE (below min score threshold): {item['CVE_ID']} - {item['Description']}")
                    continue

            # Before anything, skip excluded patterns first
            if self._is_excluded_keyword_present(item['Description']):
                if DEBUG: print(f"[INFO] Filtering out CVE (matches an excluded keyword): {item['CVE_ID']} - {item['Description']}")
                continue

            if self.search_scope == 'products':
                if self._is_prod_keyword_present(item['Description']):
                    filtered_cves.append(item)
                else:
                    if DEBUG: print(f"[INFO] Filtering out CVE (no matching product keywords): {item['CVE_ID']} - {item['Description']}")
            elif self.search_scope == 'all_keywords':
                if self._is_prod_keyword_present(item['Description']) or \
                    self._is_summ_keyword_present(item['Description']):
                    filtered_cves.append(item)
                else:
                    if DEBUG: print(f"[INFO] Filtering out CVE (no matching general keywords): {item['CVE_ID']} - {item['Description']}")
            elif self.search_scope == 'all_cves':
                return self.cve_new_dataset

            if self.include_high_severity:
                if self._cvss_score_at_above(item['CVE_ID'], item['CVSSv3_Score'], self.high_severity_threshold):
                    if item['CVE_ID'] not in [x['CVE_ID'] for x in filtered_cves]:
                        print(f"[INFO] Keeping High Severity CVE (include_high_severity enabled): {item['CVE_ID']}")
                        filtered_cves.append(item)
                    else:
                        if DEBUG: print(f"[DBG] Skipping {item['CVE_ID']} because it's already in the results list")
                else:
                    if DEBUG: print(f"[INFO] Filtering out CVE (no match on preferences and not a high enough severity score): {item['CVE_ID']} - {item['Description']}")

        self.cve_new_dataset = filtered_cves
        return


    def _cvss_score_at_above(self, cve, cvss_score: float, threshold: float):
        val = False
        if not cvss_score:
            #print(f"[DBG] {cve} has no CVSS Score")
            return val
        try:
            val = float(cvss_score) >= float(threshold)
        except ValueError:
            if DEBUG: print("[DBG] ValueError evaluating CVSS Score to threshold, CVSS Score is: {}".format(cvss_score))
        return val


    def _is_summ_keyword_present(self, summary: str):
        """ Given the summary check if any keyword is present """
        return any(w in summary for w in self.description_keywords) or \
            any(w.lower() in summary.lower() for w in self.description_keywords_i)


    def _is_prod_keyword_present(self, products: str):
        """ Given the summary check if any keyword is present """
        return any(w in products for w in self.product_keywords) or \
            any(w.lower() in products.lower() for w in self.product_keywords_i)


    def _is_excluded_keyword_present(self, summary: str):
        """ return True if an excluded keyword is in the summary/description. """
        return any(w in summary for w in self.excluded_keywords)


    def check_cve_has_exploit(self):
        """ Search CVE's from our results to the exploit mapping to see if an Exploit-DB ID is listed. If so, add this to the dataset. """
        if not self.cve_new_dataset or not self.exploit_map:
            print("[!] Either your new CVEs dataset has no notable CVE's or the Exploit mapping data is not loaded, skipping exploit ID search")
            return

        for item in self.cve_new_dataset:
            if item['CVE_ID'] in [w['CVE_ID'] for w in self.exploit_map]:
                if DEBUG: print(f"[DBG] CVE ({item['CVE_ID']} matches an exploit ID mapping")
                for node in self.exploit_map:
                    if node['CVE_ID'] == item['CVE_ID']:
                        # TODO: Would a CVE have more than one exploit id mapping in this file?
                        item['ExploitDB_ID'] = node['ExploitDB_ID']
        return


    def download_exploit_mapping(self):
        """ Retrieve the current MITRE Exploit-DB mapping dataset to use locally. """
        date_threshold = datetime.datetime.now() - datetime.timedelta(days=int(self.mitre_interval))
        if os.path.exists(self.mitre_exploit_file):
            if self.last_mitre_retrieval < date_threshold:
                if DEBUG: print("[DBG] Last MITRE data retrieval is before threshold, will get fresh data")
            else:
                if DEBUG: print("[DBG] Last MITRE data retrieval is fresh and will be used")
                return
        url_mitre = "https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html"
        csv_file = open(self.mitre_exploit_file, 'w')
        csv_writer = csv.writer(csv_file)

        response = requests.get(url_mitre, allow_redirects=True)

        if response.status_code == 200:
            print(f"[*] Response: {response.status_code} - Successfully fetched MITRE Exploit-DB mapping resource")
        else:
            print(f"[!] Could not connect to retrieve MITRE Exploit mapping resource file, try again later")
            return
        # Parse the html and extract the tables we need
        soup = BS(response.text, "html.parser")
        try:
            table = soup.find_all("table", attrs={"cellpadding": "2", "cellspacing": "2", "border": "2"})[1]
        except IndexError as e:
            print("[!] Invalid soup query, table is empty. Skipping parsing of the online resource")
            return
        headings = ["ExploitId", "CveId"]
        datasets = []
        for row in table.find_all("tr")[0:]:
            row = list(td.get_text() for td in row.find_all("td"))
            datasets.append(row)

        # Create Pandas dataframe to hold this data
        df = pd.DataFrame(datasets, columns=headings)   # Create dataframe with headings and the datasets
        df = df.astype('string')    # Convert padas objects (the default) to strings
        df.drop(df.tail(2).index, inplace=True) # Drop last two rows because they don't contain Exploit-db ID's
        df[headings[0]] = df[headings[0]].str.replace(r'\D', '', regex=True) # removing the prefix "EXPLOIT-DB" from the ExploitDBId column
        df[headings[1]] = df[headings[1]].str.rstrip("\n") # removing the trailing newline from the CVEId column
        df[headings[1]] = df[headings[1]].str.lstrip(' ') # removing the leading white space from the CVEId column
        df[headings[1]] = df[headings[1]].str.split(' ') # splitting the column based on white space within the entries
        df = df.set_index([headings[0]])[headings[1]].apply(pd.Series).stack().reset_index().drop('level_1',axis = 1).rename(columns = {0: headings[1]}) # creating multiple rows for exploits that correspond to multiple CVE #'s

        n = len(df[headings[1]])
        csv_writer.writerow(headings)
        for i in range(n-1):
            csv_writer.writerow(df.loc[i])  # Write dataframe row to CSV file
        csv_file.close()

        df.to_json(SAVE_DIR / "mitre_exploit_data.json", indent=2, orient='records') # Finally, write entire dataset to json
        now = datetime.datetime.now()
        self.last_mitre_retrieval = now.strftime(self.time_format)
        return


    def get_github_exclusions_addendum(self):
        """ From the config, send over the URL-formatted query addendum to tune all built URLs. """
        return self.gitdork_excluded_repos_string


# NVD API Notes:
    # E.g. requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev", headers=headers)
    #kev_query = "hasKev"

    # param "keywordSearch" returns any CVE where a word or phrase is found in the description
    # param "keywordExactMatch" is a toggle, that when present in the query, finds only exact matches
    #   E.g. https://api/2.0?keywordSearch=Microsoft Outlook&keywordExactMatch

    # date values must be in ISO-8061 date/time format:
    # [YYYY]["-"][MM]["-"][DD]["T"][HH][":"][SS][Z]     ?lastModStartDate=2022-08-04T13:00:00

    # page limit / resultsPerPage - default value and max page limit is 2,000 results

# -=- End of Class -=-




if __name__ == '__main__':
    # This isn't intended to be the way this file is run,
    # just an example for use in a separate file (e.g. newbot.py)
    retriever = CVERetrieverNVD()
    data = retriever.get_new_cves()
    if data:
        for item in data:
            descrip = item['Description'] if len(item["Description"]) < 200 else item["Description"][:200] + "..."
            print(f"[*] {item['CVE_ID']} - CVSS: {item['CVSSv3_Score']} - {descrip}\n")
    else:
        print("[*] No new CVE's matching your search scope for this collection cycle")
