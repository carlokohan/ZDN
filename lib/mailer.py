import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

class Emailer:
    def __init__(self, cve_data):
        self.download_loc = '/home/xxx/tmp/cve/deltaCves/'
        self.CVE_data = cve_data

    def append_to_list(self, remaining_cve):
        for cve_id in remaining_cve:
            file_h = open("/home/xxx/tmp/zdn_cves_sent.txt", "a")  # append mode
            file_h.write(cve_id + "\n") 
            file_h.close() 

    def get_not_yet_seen_cve(self):
        dct = {}
        extracted = list(self.CVE_data .keys())
        with open("/home/xxx/tmp/zdn_cves_sent.txt") as file_in:
            lines = file_in.read().splitlines()
            for cve_id in extracted:
                if cve_id not in lines:
                    dct[cve_id] = self.CVE_data[cve_id]

        return dct

    #dict of CVE_id -> keyword, attachment of JSON file
    def send(self, cve_data, score):
        remaining_cve = self.get_not_yet_seen_cve()
        print(remaining_cve)
        if remaining_cve:
            host = "smtp.xxx.com"
            server = smtplib.SMTP(host)
            
            message = MIMEMultipart('mixed')
            message['From'] = "email@xxx.com"
            message['To'] = "@xxx.com"
            message['Subject'] = 'CVE Advanced Notification'

            message_content = 'Hi Team,<br><br>New CVEs matched our keywords. See CVE and description mapping below.<br>Attached are the details for each CVE. Please check if we are affected.<br><br> <table style="border: 1px solid black"><tr><th>CVE_ID</th><th>CVSS Score</th><th>CVE Details</th></tr>'
            for cve_id in remaining_cve:
                message_content = message_content + '<tr><td style="border: 1px solid black">' + cve_id + '</td><td style="border: 1px solid black">'
                if cve_id in score:
                    message_content = message_content + score[cve_id]
                else:
                    message_content = message_content + 'n/a'

                message_content = message_content + '</td><td style="border: 1px solid black">'+ remaining_cve[cve_id] + '</td></tr>'

            message_content = message_content + "</table><br><br><br>Regards,<br>CVE Advanced Notification"
            body = MIMEText(message_content, 'html')
            message.attach(body)


            for cve_id in remaining_cve:
                attachmentPath = self.download_loc + cve_id + '.json'
                with open(attachmentPath, "rb") as attachment:
                    p = MIMEApplication(attachment.read(),_subtype="txt")
                    p.add_header('Content-Disposition', "attachment; filename= %s" % attachmentPath)
                    message.attach(p)

            msg_full = message.as_string()
            FROM = "email@xxx.com"
            TO = "email@xxx.com"
            server.sendmail(FROM, TO, msg_full)

            server.quit()
            print("Email sent!")

            self.append_to_list(remaining_cve)
        else:
            print("No new CVEs.")

