import json
import os
import re


class Search:
    def __init__(self):
        self.download_loc = '/tmp/cve/deltaCves/'
        self.CVE_data = {}

    #return dictionary of keyword -> CVE mapping and CVE -> url/details
    def search_keys(self, keywords):
        dir_list = os.listdir(self.download_loc)

        for file_name in dir_list:
            data = ''
            print("\nSearching keywords from the file " + file_name)
            with open(self.download_loc + file_name) as f_handler:
                data = json.load(f_handler)
            
            #print(data["containers"]["cna"]["descriptions"][0]["value"])
            for word in keywords:
                print("\tSearching " + word)
                target_str = data["containers"]["cna"]["descriptions"][0]["value"]
                #target_str = target_str.lower()

                regex = r".*" + word + r".*"
                if re.search(regex, target_str, re.IGNORECASE):
                    cve_id = data["cveMetadata"]["cveId"]
                    if cve_id in self.CVE_data:
                        self.CVE_data[cve_id] = self.CVE_data[cve_id] + ', ' + word
                    else: 
                        self.CVE_data[cve_id] = target_str

        return self.CVE_data
