"""
Helper utilities to query Github API and organize
metadata of repo count, stars, etc, related to a
partificular keyword search, such as a CVE.
"""
import json
import operator
from dataclasses import dataclass
from time import sleep

import requests

from core.formatters import convert_string_to_datetime


@dataclass
class Repository():
    name: str
    full_name: str
    url: str
    language: str
    description: str
    # related_cve: str
    stars: str
    # discovered_on: str
    last_pushed: str




def search_github(cve, throttle=False):
    url = f"https://api.github.com/search/repositories?q={cve}"

    if throttle:
        sleep(3)

    sleep(0.5)
    response = requests.get(url)

    if response.status_code != 200:
        print(f"[!] Response not 200, failed search for CVE: {cve} | Response code: {response.status_code}")
        return 403

    data = json.loads(response.text)
    # log.debug(f"Response data keys: {data.keys()}")
    results = data.get('items')
    data_organized = []
    if results:
        for item in results:
            # print(f"[DBG] {item=}")
            if not item.get('description'):
                item['description'] = ""
            if not item.get('language'):
                item['language'] = ''

            formatted_pushed = convert_string_to_datetime(item.get('pushed_at'))
            repo_record = Repository(
                name = item['name'],
                full_name = item['full_name'],
                url = item['html_url'],
                language = item['language'],
                # description = item.get('description', ""),
                description = item['description'],
                stars = item.get('stargazers_count', 0),
                last_pushed = formatted_pushed
            )
            data_organized.append(repo_record)

        # Sorting by most stars
        data_organized = sorted(data_organized, key=operator.attrgetter('stars'), reverse=True)
    return data_organized


