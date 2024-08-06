# ZDN
Zero-Day Notifier

To run:

`python3 /home/xxx/ZDN/zdn.py`

You can create a cron job to run it every hour because the repository that it checks for CVE updates hourly

`0 * * * * /usr/bin/python3 /home/xxx/ZDN/zdn.py`

Note: You will have to update the mailer and change the hardcoded paths on these files:
- lib/helper.py
- lib/mailer.py
- lib/search.py
- zdn.py
