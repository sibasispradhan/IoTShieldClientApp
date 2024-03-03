import os
import sys
import csv
import numpy as np
import pandas as pd
import pickle
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from dotenv import load_dotenv
load_dotenv() ## load all the env valriable

import warnings
warnings.filterwarnings("ignore")

class CustomData:
    def __init__(self,
                 httprequestmethod: str,
                 httpresponse: float,
                 tcpack: float,
                 tcpack_raw: float,
                 tcpchecksum: float,
                 tcpconnectionfin: float,
                 tcpconnectionrst: float,
                 tcpconnectionsyn: float,
                 tcpconnectionsynack: float,
                 tcpdstport: float,
                 tcpflags: float,
                 tcpflagsack: float,
                 tcplen: float,
                 tcpseq: float,
                 tcpsrcport: float,
                 udpport: float,
                 udpstream: float,
                 mqttconflagcleansess: float,
                 mqttconflags: float,
                 mqtthdrflags: float,
                 mqttlen: float,
                 mqttmsgtype: float,
                 mqttproto_len: float,
                 mqtttopic_len: float
                 ):

        self.httprequestmethod = httprequestmethod
        self.httpresponse = httpresponse
        self.tcpack = tcpack
        self.tcpack_raw = tcpack_raw
        self.tcpchecksum = tcpchecksum
        self.tcpconnectionfin = tcpconnectionfin
        self.tcpconnectionrst = tcpconnectionrst
        self.tcpconnectionsyn = tcpconnectionsyn
        self.tcpconnectionsynack = tcpconnectionsynack
        self.tcpdstport = tcpdstport
        self.tcpflags = tcpflags
        self.tcpflagsack = tcpflagsack
        self.tcplen = tcplen
        self.tcpseq = tcpseq
        self.tcpsrcport = tcpsrcport
        self.udpport = udpport
        self.udpstream = udpstream
        self.mqttconflagcleansess = mqttconflagcleansess
        self.mqttconflags = mqttconflags
        self.mqtthdrflags = mqtthdrflags
        self.mqttlen = mqttlen
        self.mqttmsgtype = mqttmsgtype
        self.mqttproto_len = mqttproto_len
        self.mqtttopic_len = mqtttopic_len

    def get_data_as_dataframe(self):
        try:
            custom_data_input_dict = {
                'http.request.method': [self.httprequestmethod],
                'http.response': [self.httpresponse],
                'tcp.ack': [self.tcpack],
                'tcp.ack_raw': [self.tcpack_raw],
                'tcp.checksum': [self.tcpchecksum],
                'tcp.connection.fin': [self.tcpconnectionfin],
                'tcp.connection.rst': [self.tcpconnectionrst],
                'tcp.connection.syn': [self.tcpconnectionsyn],
                'tcp.connection.synack': [self.tcpconnectionsynack],
                'tcp.dstport': [self.tcpdstport],
                'tcp.flags': [self.tcpflags],
                'tcp.flags.ack': [self.tcpflagsack],
                'tcp.len': [self.tcplen],
                'tcp.seq': [self.tcpseq],
                'tcp.srcport': [self.tcpsrcport],
                'udp.port': [self.udpport],
                'udp.stream': [self.udpstream],
                'mqtt.conflag.cleansess': [self.mqttconflagcleansess],
                'mqtt.conflags': [self.mqttconflags],
                'mqtt.hdrflags': [self.mqtthdrflags],
                'mqtt.len': [self.mqttlen],
                'mqtt.msgtype': [self.mqttmsgtype],
                'mqtt.proto_len': [self.mqttproto_len],
                'mqtt.topic_len': [self.mqtttopic_len]
            }
            df = pd.DataFrame(custom_data_input_dict)

            return df
        except Exception as e:
            print(e)

    def to_dict(self):
        # Convert object attributes to a dictionary
        return {
            'httprequestmethod': self.httprequestmethod,
            'httpresponse': self.httpresponse,
            'tcpack': self.tcpack,
            'tcpack_raw': self.tcpack_raw,
            'tcpchecksum': self.tcpchecksum,
            'tcpconnectionfin': self.tcpconnectionfin,
            'tcpconnectionrst': self.tcpconnectionrst,
            'tcpconnectionsyn': self.tcpconnectionsyn,
            'tcpconnectionsynack': self.tcpconnectionsynack,
            'tcpdstport': self.tcpdstport,
            'tcpflags': self.tcpflags,
            'tcpflagsack': self.tcpflagsack,
            'tcplen': self.tcplen,
            'tcpseq': self.tcpseq,
            'tcpsrcport': self.tcpsrcport,
            'udpport': self.udpport,
            'udpstream': self.udpstream,
            'mqttconflagcleansess': self.mqttconflagcleansess,
            'mqttconflags': self.mqttconflags,
            'mqtthdrflags': self.mqtthdrflags,
            'mqttlen': self.mqttlen,
            'mqttmsgtype': self.mqttmsgtype,
            'mqttproto_len': self.mqttproto_len,
            'mqtttopic_len': self.mqtttopic_len
        }

def load_object(file_path):
    try:
        with open(file_path,'rb') as file_obj:
            return pickle.load(file_obj)
    except Exception as e:
        print(f'error in load pickel {e}')

def save_csv(csv_file_path,output_line):
    try:
        csv_file_exists = False
        try:
            with open(csv_file_path, 'r'):
                csv_file_exists = True
        except FileNotFoundError:
            pass
        with open(csv_file_path, 'a', newline='') as csv_file:
            # Create a CSV writer
            csv_writer = csv.writer(csv_file)

            # If the CSV file doesn't exist, write the header
            if not csv_file_exists:
                header = [
                    'frame.time','ip.src_host','ip.dst_host','arp.dst.proto_ipv4','arp.opcode','arp.hw.size',
                    'arp.src.proto_ipv4','icmp.checksum','icmp.seq_le','icmp.transmit_timestamp','icmp.unused',
                    'http.file_data','http.content_length','http.request.uri.query','http.request.method','http.referer',
                    'http.request.full_uri','http.request.version','http.response','http.tls_port','tcp.ack','tcp.ack_raw',
                    'tcp.checksum','tcp.connection.fin','tcp.connection.rst','tcp.connection.syn','tcp.connection.synack',
                    'tcp.dstport','tcp.flags','tcp.flags.ack','tcp.len','tcp.options','tcp.payload','tcp.seq','tcp.srcport',
                    'udp.port','udp.stream','udp.time_delta','dns.qry.name','dns.qry.name.len','dns.qry.qu','dns.qry.type',
                    'dns.retransmission','dns.retransmit_request','dns.retransmit_request_in','mqtt.conack.flags',
                    'mqtt.conflag.cleansess','mqtt.conflags','mqtt.hdrflags','mqtt.len','mqtt.msg_decoded_as','mqtt.msg',
                    'mqtt.msgtype','mqtt.proto_len','mqtt.protoname','mqtt.topic','mqtt.topic_len','mqtt.ver','mbtcp.len',
                    'mbtcp.trans_id','mbtcp.unit_id','Attack_label','Attack_type'
                ]
                csv_writer.writerow(header)

            # Write the data into the CSV file
            csv_writer.writerow(output_line.split(','))

    except Exception as e:
        print(e)

def predict(features):
    try:
        features['http.request.method'] = features['http.request.method'].astype(str)
        preprocessor_path=os.path.join("artifacts","preprocessor.pkl")
        model_path=os.path.join("artifacts","model.pkl")

        preprocessor=load_object(preprocessor_path)
        model=load_object(model_path)
        #print(f'processor: {preprocessor}, model: {model}')    
        scaled_fea=preprocessor.transform(features)
        attack_label = int(model.predict(scaled_fea)[0])
        #print(f'ml predit attack label : {attack_label}')
        attack_type = 'Normal'
        if attack_label==1:
            preprocessor2_path=os.path.join("artifacts","preprocessor2.pkl")
            model2_path=os.path.join("artifacts","model2.pkl")
            
            preprocessor2=load_object(preprocessor2_path)
            model2=load_object(model2_path)
            
            scaled2_fea=preprocessor2.transform(features)
            pred = model2.predict(scaled2_fea)
            attack_type = pred[0] 
            
        return attack_type, attack_label

    except Exception as e:
        error_message = "An error occurred: {}".format(e)
        print(error_message)

def send_email(subject, body_html, attachment_path, to_emailid):
    # Set up the email server and login credentials
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_EMAIL_ID")
    smtp_password = os.getenv("SMTP_EMAIL_PWD")
    if to_emailid != '':
        to_email = to_emailid
    else:
        to_email = os.getenv("EMAIL_TO")
    cc_email = os.getenv("EMAIL_CC")
    all_recipients = to_email
    # Create the email message
    message = MIMEMultipart()
    message['From'] = smtp_username
    message['To'] = to_email
    if cc_email !="":
        message['Cc'] = cc_email
        all_recipients = [to_email] + [cc_email]
    message['Subject'] = subject

    # Attach the body of the email
    #message.attach(MIMEText(body, 'plain'))
    message.attach(MIMEText(body_html, 'html'))
    if os.path.exists(attachment_path):
        # Attach the CSV file
        with open(attachment_path, 'rb') as attachment:
            csv_attachment = MIMEApplication(attachment.read(), _subtype="csv")
            csv_attachment.add_header('Content-Disposition', f'attachment; filename={attachment_path}')
            message.attach(csv_attachment)
    else:
        print(f"Warning: File not found at {attachment_path}. No attachment will be sent.")

    # Connect to the SMTP server and send the email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Use this line if your server requires a secure connection
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, all_recipients, message.as_string())
        server.quit()
        return "Email sent successfully!"
    except Exception as e:
        return f"Error sending email: {e}"

