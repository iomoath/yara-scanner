"""
Email sender with attachment support
"""

import smtplib
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import os
import sys

COMMASPACE = ', '


def send_message(dict_msg_attr):
    if dict_msg_attr is None:
        return False

    username = dict_msg_attr["username"]
    password = dict_msg_attr["password"]
    smtp_host = dict_msg_attr["host"]
    smtp_port = int(dict_msg_attr["port"])
    smtp_ssl = bool(dict_msg_attr["ssl"])
    recipients = dict_msg_attr["recipients"]
    message_body = dict_msg_attr["message_body"]

    # Create the enclosing (outer) message
    outer = MIMEMultipart()
    outer['Subject'] = dict_msg_attr["subject"]
    outer['To'] = COMMASPACE.join(recipients)
    outer['From'] = dict_msg_attr["from"]
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

    # List of attachments, dict_msg_attr["attachments"] contains a list of strings.
    # each string will be encoded and attached as a file to the message
    attachments = dict_msg_attr["attachments"]
    if attachments is not None:
        for txt_attachments in attachments:
            # Add the attachments to the message
            try:
                msg = MIMEBase('application', "octet-stream")
                msg.set_payload(bytes(txt_attachments['text'], "utf-8"))
                encoders.encode_base64(msg)
                msg.add_header('Content-Disposition', 'attachment', filename=txt_attachments['file_name'])
                outer.attach(msg)
            except:
                print("Unable to read one of the attachments. Error: ", sys.exc_info()[0])
                raise

    outer.attach(MIMEText(message_body, 'plain'))
    composed = outer.as_string()

    # send email
    try:
        with smtplib.SMTP('{}: {}'.format(smtp_host, smtp_port)) as server:
            server.ehlo()
            if smtp_ssl:
                server.starttls()
                server.ehlo()

            server.login(username, password)
            server.sendmail(dict_msg_attr["from"], recipients, composed)

            server.close()
            server.close()

            return True

    except:
        print("Sending email failed. {}".format(sys.exc_info()[0]), sys.exc_info()[0])
        raise
