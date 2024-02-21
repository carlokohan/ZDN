import argparse


def main(args):
    keyword = ""

    if args.keyword:
        keyword = args.keyword
    else:
        #get keyword from file
        if args.input:
            #read file
            print('reading input file '+args.input)
            keyword = args.input
            #keyword = get_from_input()
        else:
            #read from default location under files/keywords.txt
            print('reading from files/keywords.txt')
            #keyword = get_from_default_file()
            keyword = 'files/keywords.txt'

    print(keyword)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search keywords from CVE and ZDI and emails you the findings')

    parser.add_argument('-k','--keyword', type=str, help='Comma separated value of keywords you want to search.')
    parser.add_argument('-i','--input', type=str, help='Absolute path of file with keywords.')
    args = parser.parse_args()

    main(args)
