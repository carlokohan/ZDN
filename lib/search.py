import json
import os
import re


class Search:
    def __init__(self):
        self.download_loc = '/home/xxx/tmp/cve/deltaCves/'
        self.CVE_data = {}
        self.CVE_score = {}

    #return dictionary of keyword -> CVE mapping and CVE -> url/details
    def search_keys(self, keywords, keywords_acronyms, year):
        dir_list = os.listdir(self.download_loc)

        for file_name in dir_list:
            if year not in file_name:
                print('Current year ' + year + ' not in file name. Skipping...')
                continue

            data = ''
            cve_id = ''
            #print("\nSearching keywords from the file " + file_name)
            with open(self.download_loc + file_name) as f_handler:
                data = json.load(f_handler)
            
            for word in keywords:
                #print("\tSearching " + word)

                if "descriptions" in  data["containers"]["cna"]:
                    target_str = data["containers"]["cna"]["descriptions"][0]["value"]
                    #target_str = target_str.lower()

                    regex = r".*" + word + r".*"
                    if re.search(regex, target_str, re.IGNORECASE):
                        cve_id = data["cveMetadata"]["cveId"]
                        if cve_id in self.CVE_data:
                            self.CVE_data[cve_id] = self.CVE_data[cve_id] + ', ' + word
                        else: 
                            self.CVE_data[cve_id] = target_str

                if "metrics" in data["containers"]["cna"]:
                    if "cvssV3_1" in data["containers"]["cna"]["metrics"][0]:
                        score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
                        severity = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseSeverity"]
                        self.CVE_score[cve_id] = ''+ str(score) + ' - ' + severity
                else:
                    self.CVE_score[cve_id] = 'No CVSS score yet.'

            for word in keywords_acronyms:
                if "descriptions" in  data["containers"]["cna"]:
                    target_str = data["containers"]["cna"]["descriptions"][0]["value"]

                    regex = r"\S+ " + word + r" \S+"
                    if re.search(regex, target_str, re.IGNORECASE):
                        cve_id = data["cveMetadata"]["cveId"]
                        if cve_id in self.CVE_data:
                            self.CVE_data[cve_id] = self.CVE_data[cve_id] + ', ' + word
                        else: 
                            self.CVE_data[cve_id] = target_str
        return self.CVE_data

    def get_score(self):
        return self.CVE_score
