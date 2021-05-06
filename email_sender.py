"""
Email sender with attachment support
"""

import smtplib
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import sys
import ssl
import settings


COMMASPACE = ', '



def send(sender, recipients, composed):
    if settings.SMTP_SEC_PROTOCOL == "ssl":
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, ssl.create_default_context()) as server:
            server.ehlo_or_helo_if_needed()
            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True
    elif settings.SMTP_SEC_PROTOCOL == "tls":
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.ehlo_or_helo_if_needed()

            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True
    else:
        with smtplib.SMTP(settings.SMTP_HOST) as server:
            server.ehlo_or_helo_if_needed()

            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True


def send_message(dict_msg_attr):
    if dict_msg_attr is None:
        return False

    recipients = settings.TO
    message_body = dict_msg_attr["message"]
    sender = "{} <{}>".format(settings.FROM_NAME, settings.FROM)

    # Create the enclosing (outer) message
    outer = MIMEMultipart()
    outer['Subject'] = dict_msg_attr["subject"]
    outer['To'] = COMMASPACE.join(recipients)
    outer['From'] = sender
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

    # List of attachments, dict_msg_attr["attachments"] contains a list of strings.
    # each string will be encoded and attached as a file to the message.
    if 'attachments' in dict_msg_attr and  dict_msg_attr["attachments"] is not None:
        attachments = dict_msg_attr["attachments"]
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
        send(sender, recipients, composed)
    except:
        print("Sending email failed. More info {}: ".format(sys.exc_info()[0]), sys.exc_info()[0])
        raise