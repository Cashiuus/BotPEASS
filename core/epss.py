# EPSS API Integration class
#

import os
import sys
from datetime import datetime
from pathlib import Path
from time import sleep

import requests


# APP_DIR = Path(__file__).resolve(strict=True).parent.parent
# SOT_DIR = APP_DIR / "datasets"




class EPSSGopher(object):
    """
    An API integration retriever for EPSS scores (first.org/epss)


    EPSS Scores             A CVE's probability score ranging from 0-1;
                            higher score = higher likelihood of exploitation

    EPSS Percentiles        A CVE's percentile indicates how likely it is to be
                            exploited compared to other vulns. Ex: 90 means it
                            has a higher probability of exploitation than 90% of all
                            other CVEs/Vulns in the group.

    """
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
        self.api_key = None         # currently, api seems to be open to public, no key needed
        # self.sot_dir = SOT_DIR

        self.cached_scores = {}     # dict - e.g.: {'CVE-2023-0001': 0.293344}
        self.get_cached_score_tuples = {}    # dict - {'CVE_2023-20268': (score, percentile)}
        return


    def get_cached_score(self, cve):
        """
        If we've already grabbed a CVE's score during this session, use it instead of
        making redundant remote requests.

        TIP: This efficiency add-in exponentially increased the performance of EPSS score enriching.
        A file that before took 2m29s to process, only took 12s to process with this caching in place.
        """
        if cve in self.cached_scores.keys():
            score = self.cached_scores.get(cve)
            if score:
                return score
            else:
                # log.debug(f"Something went wrong, cve is in cache, but score is empty")
                return


    def get_score_for_cve(self, cve: str):
        """
            Get the EPSS score in its native format and return it back.

            return :float
        """
        if cve in self.cached_scores.keys():
            score = self.get_cached_score(cve)
            if score:
                return score

        # url = f"{self.base_url}"
        params = {
            'cve': f"{cve}"
        }

        try:
            response = requests.get(
                url=self.base_url,
                params=params
            )
        except Exception as e:
            print(f"[ERR] Exception during get request: {e}")
            return

        if response.status_code != 200:
            # log.debug(f" Response not 200 code: {response.status_code}")
            if response.json().get('total') == 0:
                # log.debug(f"Response json total value is 0, something is wrong")
                return

        # Response will be JSON
        # -- Example Response JSON Contents:
        # {'status': 'OK', 'status-code': 200, 'version': '1.0', 'access': 'public',
        # 'total': 1, 'offset': 0, 'limit': 100, 'data': [{'cve': 'CVE-2023-26568',
        # 'epss': '0.000440000', 'percentile': '0.086000000', 'date': '2023-10-25'}]}
        # --

        # log.debug(f"Response (code: {response.status_code}) raw json: {response.json()}")
        # log.debug("---------------- END OF JSON ----------------")
        # NOTE: There are cases where the EPSS response 'data' is empty, if it doesn't have
        # a value for newer CVE's yet. In thise case, data will be empty.
        response_data = response.json().get("data")
        if not response_data:
            # log.debug("See the response raw json in previous debug, data is empty, so no EPSS value calculated for this CVE yet?")
            return

        epss_raw_score = response.json().get("data")[0].get("epss")
        # epss_raw_percentile = response.json().get("data")[0].get("percentile")
        # percentage = float(score) * 100
        # log.debug(f"Raw score extracted is: {score} - percentage: {percentage}%")

        self.cached_scores[cve] = epss_raw_score
        return epss_raw_score


    def get_score_tuple_for_cve(self, cve: str):
        """
            Get the EPSS score in its native format and return it back.

            return (score, percentile)
        """
        if cve in self.get_cached_score_tuples.keys():
            # NOTE: This should still work if value is a tuple, just make sure to handle it correctly
            score_tuple = self.get_cached_score(cve)
            if score_tuple:
                return score_tuple

        # Otherwise, not cached so fetch it

        # url = f"{self.base_url}"
        params = {
            'cve': f"{cve}"
        }

        try:
            response = requests.get(
                url=self.base_url,
                params=params
            )
        except Exception as e:
            print(f"[ERR] Exception during get request: {e}")
            return None, None

        if response.status_code != 200:
            # log.debug(f" Response not 200 code: {response.status_code}")
            if response.json().get('total') == 0:
                # log.debug(f"Response json total value is 0, something is wrong")
                return None, None

        # -- Example Response JSON Contents:
        # {'status': 'OK', 'status-code': 200, 'version': '1.0', 'access': 'public', 'total': 1, 'offset': 0, 'limit': 100,
        # 'data': [
        #   {'cve': 'CVE-2023-26568', 'epss': '0.000440000', 'percentile': '0.086000000', 'date': '2023-10-25'}
        # ]}
        # --

        # log.debug(f"Response (code: {response.status_code}) raw json: {response.json()}")
        # log.debug("---------------- END OF JSON ----------------")
        # NOTE: There are cases where the EPSS response 'data' is empty, if it doesn't have
        # a value for newer CVE's yet. In thise case, data will be empty.
        response_data = response.json().get("data")
        if not response_data:
            # log.debug("See the response raw json in previous debug, data is empty, so no EPSS value calculated for this CVE yet?")
            return None, None

        epss_raw_score = response.json().get("data")[0].get("epss")
        epss_raw_percentile = response.json().get("data")[0].get("percentile")
        # percentage = round(float(score) * 100, 2)
        # log.debug(f"Raw score extracted is: {epss_raw_score} - percentage: {percentage}%")

        self.cached_scores[cve] = (epss_raw_score, epss_raw_percentile)
        return (epss_raw_score, epss_raw_percentile)


    def get_scores_for_cves_list(self, cves: list) -> dict:
        """
        Get EPSS scores for a list of CVE's

        return  dict of cve, score, percentile, date

        """
        cves_formatted = ",".join([x.strip() for x in cves])
        cve_scores = []

        params = {
            'cve': f"{cves_formatted}"
        }

        try:
            response = requests.get(
                url=self.base_url,
                params=params
            )
        except Exception as e:
            print(f"[ERR] Exception during get request: {e}")
            # log.error(f"Exception during get request: {e}")
            return

        if response.status_code != 200:
            # log.debug(f" Response not 200 code: {response.status_code}")
            if response.json().get('total') == 0:
                # log.debug(f"Response is valid but there are no results and json is empty")
                pass
            return

        # Response will be JSON
        # log.debug(f"Response raw json: {response.json()}")
        # log.debug("---------------- END OF JSON ----------------")
        total = response.json().get("total")
        offset = response.json().get("offset")

        cve_scores = response.json().get("data")
        if not isinstance(cve_scores, list):
            # log.debug(f"cve_scores should be list of dicts but isn't, type is: {type(cve_scores)}")
            return
        # This should be a list of the results, each record looks like this:
            # {'cve': 'CVE-2018-10562', 'epss': '0.975880000', 'percentile': '1.000000000', 'date': '2023-05-02'},

        for result in cve_scores:
            if result.get("cve") and result.get("epss"):
                self.cached_scores[result['cve']] = result['epss']

        # log.debug(f"cve_scores contains {len(cve_scores):,d} results")
        return cve_scores    # list of {cve:score} dicts that will need to be * 100 to get percentage


    def get_highest_epss_from_cves_list(self, cves: list, calc_method="top"):
        """
        A wrapper around the above method, get_scores_for_cves_list(), but after
        getting the dict of CVE's and scores, determine the highest EPSS from the list and return that value

        This is useful when, for example, you have a list of CVE's related to a single finding and want
        to leverage the highest EPSS of the bunch in order to determine how to prioritize that finding.

        Optionally, the calc_method can be specified if you want to pick from choices how the returned value
        is calculated.

        calc_method:    "top" or "avg"
        return          score int|float
        """
        score = None
        epss_results = self.get_scores_for_cves_list(cves)
        if epss_results:
            epss_scores = [v for k,v in epss_results.items() if k == "epss"]
            # log.debug(f"{epss_results=}")
            # log.debug(f"{epss_scores=}")
            if calc_method == "top":
                score = max(epss_scores)
            elif calc_method in ["avg", "average"]:
                score = sum(epss_scores) / len(epss_scores)

        # percentage = float(score) * 100
        # log.debug(f"Raw score extracted is: {score} - percentage: {percentage}%")
        return score


    def get_most_exploitable_cves(self, max_limit=25) -> list:
        """"
        Query EPSS and return the top "max_limit" with the highest EPSS scores, no other conditions.
        This one incorporates pagination collection to get all results.

        return a list
        """

        cves_only = set()
        dataset = []

        # First request
        params = {
            "percentile-gt": "0.95",
            "order": "!epss"
        }

        try:
            response = requests.get(
                url=self.base_url,
                params=params
            )
        except Exception as e:
            print(f"[ERR] Exception during get request: {e}")
            # log.error(f"Exception during get request: {e}")
            return

        if response.status_code != 200:
            # log.error(f" Response not 200 code: {response.status_code}")
            if response.json().get('total') == 0:
                # log.debug(f"Response is valid but there are no results and json is empty")
                pass
            return

        # log.debug(response.json())

        total = int(response.json().get("total"))
        limit = int(response.json().get("limit"))       # This defaults to 100, and seems to be the max
        # offset = int(response.json().get("offset"))

        # TODO: Are these unique CVE's or could be same CVE with scores from different dates?
        # log.info(f"Query has {total:,d} total results")

        cve_scores = response.json().get("data")
        if not isinstance(cve_scores, list):
            # log.debug(f"cve_scores should be list of dicts but isn't, type is: {type(cve_scores)}")
            return
        # Create a basic list of CVE's that we can ensure there aren't duplicates
        # TODO: If dupes exist, we'll just want the newest ones based on date field
        for node in cve_scores:
            cves_only.add(node["cve"])

        if total > max_limit:
            # Trim down the results to our max limit value, ensuring that the top scored stay first
            dataset.extend(cve_scores[0:max_limit])
        else:
            dataset.extend(cve_scores)

        # Only paginate and get more if our max_limit threshold is over the # on first page
        if max_limit > 100:
            # -- Additional requests until we fully paginate through all results
            counter = 0
            while counter < total and counter < max_limit:
                # Kindness ya'll
                sleep(1)

                params = {
                    "percentile-gt": "0.95",
                    "order": "!epss",
                    "offset": f"{counter}",
                    "limit": "100"
                }

                try:
                    response = requests.get(
                        url=self.base_url,
                        params=params
                    )
                except Exception as e:
                    print(f"[ERR] Exception during get request: {e}")
                    # log.error(f"Exception during get request: {e}")
                    return

                if response.status_code != 200:
                    # log.debug(f" Response not 200 code: {response.status_code}")
                    return

                # log.info(f"Gathering request results ({counter:,d}/{total:,d})...")

                # Update our offset for the next request
                limit = int(response.json().get("limit"))
                counter = counter + limit

                cve_scores = response.json().get("data")
                if not isinstance(cve_scores, list):
                    # log.debug(f"cve_scores should be list of dicts but isn't, type is: {type(cve_scores)}")
                    return

                for node in cve_scores:
                    cves_only.add(node["cve"])

                dataset.extend(cve_scores)

            # -- end of pagination loop

        print(f"[*] Total unique CVEs in results: {len(cves_only):,d}")
        print(f"[*] Total CVE entries in dataset: {len(dataset):,d}")
        return dataset


# -+- End of Class -+-




if __name__ == '__main__':
    gopher = EPSSGopher()

    # Test Method 1
    cve = "CVE-2022-27225"
    score = gopher.get_score_for_cve(cve)
    score_percentage = float(score) * 100
    if score_percentage:
        print(f"[*] {cve} has EPSS (probability) of: {score_percentage}%")
    else:
        print("[-] No score found, sad-face...")

    # Test Method 2
    cves = ["CVE-2022-27225", "CVE-2023-27223", "CVE-2023-27218"]
    results = gopher.get_score_for_cves_list(cves)
    if results:
        print("{:^20} {:^15} {:^13} {:^13}".format("CVE", "EPSS", "Percentile", "Date"))
        print("=" * 60)
        for cve in results:
            print(f"{cve['cve']:<20} {cve['epss']:<15} {cve['percentile']:<13} {cve['date']:<13}")
        print()
    else:
        print("[-] No results! Check and try again")

    # Test Method 3
    print("[*] Retrieving the most exploitable CVEs dataset, please wait...")
    dataset = gopher.get_most_exploitable_cves(max_limit=50)
    print("[*] Top 50 Exploitable CVEs")
    if dataset:
        print("{:^20} {:^15}".format("CVE", "EPSS"))
        print("=" * 35)
    for node in dataset:
        print(f"{node['cve']:<20} {node['epss']:<15}")
    print()


