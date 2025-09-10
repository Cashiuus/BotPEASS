#!/usr/bin/env python

import argparse
import os
from time import sleep

import requests

from core.epss import EPSSGopher
from core.notifiers import generate_new_cve_message, send_slack_mesage, send_telegram_message
from core.providers import CVERetrieverNVD
from core.github import search_github

DEBUG = False



def main():
    parser = argparse.ArgumentParser(description="BOT to monitor new CVE's and send notifications as a customized vulnerability feed")
    parser.add_argument('-t', '--testing', action='store_true',
                        help='Run bot in console for testing, skipping writes to file')
    args = parser.parse_args()

    enable_github_search = True
    throttle_github_search = False

    retriever = CVERetrieverNVD(testing=args.testing)
    data = retriever.get_new_cves()
    github_query_addendum = retriever.gitdork_excluded_repos_string
    if data:
        if DEBUG: print("[DBG] data keys: {}".format(data[0].keys()))
        for item in data:
            # item is dict with keys: CVE_ID, CVSSv3_Score, Published, Description, ExploitDB_ID
            #  Exploit_References, Normal_References

            if enable_github_search:
                github_poc_count = search_github(item['CVE_ID'], throttle=throttle_github_search)
                if github_poc_count:
                    # Custom return value to indicate GitHub has throttled us
                    if github_poc_count == 403:
                        enable_github_search = False
                        print("[!] Github API Search is blocking, disabling it for this run")
                        # throttle_github_search = True
                    else:
                        github_poc_count = len(github_poc_count)
            else:
                github_poc_count = 0
            cve_message = generate_new_cve_message(item, github_addendum=github_query_addendum, github_poc_count=github_poc_count)
            # public_exploits = ''
            if item.get('ExploitDB_ID') is not None:
                print(f"\n[*] CVE *with Exploit-db ID* Message:\n{cve_message}")
            else:
                print(f"\n[*] CVE Message:\n{cve_message}")
            send_slack_mesage(cve_message)

        print(f"[*] {len(data):,d} new CVE's to report this collection cycle")
    else:
        print("[-] No new CVE's matching your search scope for this collection cycle")

    #if retriever.cve_new_dataset:
        #print("[*] Can also leverage this class attribute of the dataset. Pulled {} CVE's".format(len(retriever.cve_new_dataset)))
        #pass
    return


if __name__ == '__main__':
    main()
