import argparse
import errno
import time
import traceback

from lib.helper import Zip_Operations
from lib.mailer import Emailer
from lib.search import Search

def main(args):
    keywords = ['salesforce', 'fortinet', 'splunk', 'microsoft exchange', 'microsoft outlook', 'outlook', 'microsoft office', 'servicenow', 'fortios', 'forticlient']
    keywords_acronyms = ['aix', 'sap']
    if args.keyword:
        keywords = args.keyword
    else:
        #get keyword from file
        '''
        if args.input:
            #read file
            print('Reading input file '+args.input)
            keywords = args.input
            #keywords = get_from_input()
        else:
            #read from default location under files/keywords.txt
            print('reading from files/keywords.txt')
            #keywords = get_from_default_file()
            keywords = 'files/keywords.txt'
        '''

    print("Running...")
    zip_obj = Zip_Operations()
    zip_obj.download_cve_file()
    zip_obj.unzip_file()

    search_obj = Search()
    email_data = search_obj.search_keys(keywords, keywords_acronyms, zip_obj.get_year())

    if email_data:
        emailer = Emailer(email_data)
        emailer.send(email_data, search_obj.get_score())

    zip_obj.clean_up()

if __name__ == "__main__":
    count = 1
    while(count < 9):
        try: 
            parser = argparse.ArgumentParser(description='Search keywords from CVE and ZDI and emails you the findings')

            parser.add_argument('-k','--keyword', type=str, help='Comma separated value of keywords you want to search.')
            parser.add_argument('-i','--input', type=str, help='Absolute path of file with keywords.')
            args = parser.parse_args()

            main(args)
            count = 10 # we assume here that no errors occurred above, so we exit the script
        except Exception as exc:
            print("Error occured.")
            print(traceback.format_exc())

            if hasattr(exc,"errno") and exc.errno == errno.ENOENT:
                count = 10

            print("sleeping for 5 mins...")
            time.sleep(300)

        count = count + 1

