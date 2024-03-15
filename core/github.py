
import json
import operator
from dataclasses import dataclass

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




def search_github(cve):
    url = f"https://api.github.com/search/repositories?q={cve}"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[ERR] Response not 200, failed search for CVE: {cve}")
        return

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


