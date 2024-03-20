import os
import shutil
import time

from time import gmtime,strftime
from urllib.request import urlretrieve
from zipfile import ZipFile


class Zip_Operations:
    def __init__(self):
        self.hour = time.strftime("%I", time.gmtime())
        self.date = time.strftime("%Y-%m-%d", time.gmtime())
        #print("\nGMT: "+time.strftime("%a, %d %b %Y %I:%M:%S %p %Z", time.gmtime())
        #print("Local: "+strftime("%a, %d %b %Y %I:%M:%S %p %Z\n"))
        
        self.file_name =  self.date + "_delta_CVEs_at_" + self.hour + '00Z.zip'
        self.url = 'https://github.com/CVEProject/cvelistV5/releases/download/cve_' + self.date + '_' + self.hour + '00Z/' + self.file_name
        self.download_loc = '/tmp/cve/'
        self.cve_files_loc = '/tmp/cve/deltaCves/'

    def download_cve_file(self):
        dl_loc = self.download_loc + self.file_name
        print("Downloading from: " + self.url)

        urlretrieve(self.url, dl_loc)
        print("Finished downloading!")

    def clean_up(self):
        print("Removing contents of directory...")
        for filename in os.listdir(self.download_loc):
            file_path = os.path.join(self.download_loc, filename)
            print("deleting " + file_path)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))
        print("Done removing files from /tmp/cve/ directory!")

    def unzip_file(self):
        print("Unzipping cve file...")
        dl_loc = self.download_loc + self.file_name

        with ZipFile(dl_loc, 'r') as z_object:
            z_object.extractall(path=self.download_loc)
