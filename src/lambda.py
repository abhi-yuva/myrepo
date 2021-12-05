# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna


import os
import sys
from os.path import normpath, basename
here = os.path.dirname(os.path.realpath(__file__))
# sys.path.append(os.path.join(here, "./plugin"))
sys.path.append(os.path.join(here, "./plugin"))

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
from datetime import datetime, timedelta, date
import boto3
import json
import concurrent.futures
from botocore.exceptions import ClientError
from socket import socket
from collections import namedtuple
# datetime object containing current date and time
now = datetime.now()

left_days = 0
# now = datetime.date.today() + datetime.timedelta(-30)
 
#print("now =", now)

# dd/mm/YY H:M:S
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
#print("date and time =", dt_string)	


HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
msg = ""
expired = 0
count =0
# f = open("hostlist.txt","r")
# hostname = f.readline()
# port = f.readline()
#def ses_notification():
    # Replace sender@example.com with your "From" address.
	# This address must be verified with Amazon SES.
SENDER = "abhilashkumar.kopparapu@gmail.com"

	# Replace recipient@example.com with a "To" address. If your account 
	# is still in the sandbox, this address must be verified.
RECIPIENT = "abhilashkumar.kopparapu@gmail.com"

	# Specify a configuration set. If you do not want to use a configuration
	# set, comment the following variable, and the 
	# ConfigurationSetName=CONFIGURATION_SET argument below.
	#CONFIGURATION_SET = "ConfigSet"

	# If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
AWS_REGION = "us-west-2"

	# The subject line for the email.
SUBJECT = "Certificate Expiry Notification"

def get_alt_names(cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def print_basic_info(hostinfo):
    # global peername, commonname, SAN, notbefore, notafter
    # peername = hostinfo.peername
    # commonname = get_common_name(hostinfo.cert)
    # SAN = get_alt_names(hostinfo.cert)
    # notbefore = hostinfo.cert.not_valid_before
    # notafter = hostinfo.cert.not_valid_after
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)
    
def check_it_out(hostname, port):
    global peername, commonname, SAN, notbefore, notafter,msg,expired,count,left_days
    hostinfo = get_certificate(hostname, port)
    peername = hostinfo.peername
    commonname = get_common_name(hostinfo.cert)
    SAN = get_alt_names(hostinfo.cert)
    notbefore = hostinfo.cert.not_valid_before
    notafter = hostinfo.cert.not_valid_after
    #notification = hostinfo.cert.not_valid_after + timedelta(-30)
    print_basic_info(hostinfo)
    #getting the different between the dates

    print(now)
    left_days = (notafter - now).days
    print("Remainig Days are: ",left_days)
    
    if left_days == 30 :
        count=count+1
        expired=expired + 1
        msg+= "<tr><td>"+str(count)+"</td><td>"+hostname+"</td><td>"+str(peername)+"</td><td>"+str(commonname)+"</td><td>"+str(SAN)+"</td><td>"+str(notbefore)+"</td><td>"+str(notafter)+"</td><td style='background-color:#FF0000'>Going to Expire in" + str(left_days) +  "Days</td></tr> "
    elif left_days == 20  :
        count=count+1
        expired=expired + 1
        msg+= "<tr><td>"+str(count)+"</td><td>"+hostname+"</td><td>"+str(peername)+"</td><td>"+str(commonname)+"</td><td>"+str(SAN)+"</td><td>"+str(notbefore)+"</td><td>"+str(notafter)+"</td><td style='background-color:#FF0000'>Going to Expire in" + str(left_days) +  "Days</td></tr> "
    elif left_days == 10  :
        count=count+1
        expired=expired + 1
        msg+= "<tr><td>"+str(count)+"</td><td>"+hostname+"</td><td>"+str(peername)+"</td><td>"+str(commonname)+"</td><td>"+str(SAN)+"</td><td>"+str(notbefore)+"</td><td>"+str(notafter)+"</td><td style='background-color:#FF0000'>Going to Expire in" + str(left_days) +  "Days</td></tr> "
    elif left_days >0 and left_days <= 7  :
        count=count+1
        expired=expired + 1
        msg+= "<tr><td>"+str(count)+"</td><td>"+hostname+"</td><td>"+str(peername)+"</td><td>"+str(commonname)+"</td><td>"+str(SAN)+"</td><td>"+str(notbefore)+"</td><td>"+str(notafter)+"</td><td style='background-color:#FF0000'>Going to Expire in" + str(left_days) +  "Days</td></tr> "
    elif left_days ==0  :
        count=count+1
        expired=expired + 1
        msg+= "<tr><td>"+str(count)+"</td><td>"+hostname+"</td><td>"+str(peername)+"</td><td>"+str(commonname)+"</td><td>"+str(SAN)+"</td><td>"+str(notbefore)+"</td><td>"+str(notafter)+"</td><td style='background-color:#FF0000'>Going to Expire Today Day</td></tr> "
    
def handler(event, context):

    # Opening JSON file
    f = open('hostlist.json',"r")
    # returns JSON object as 
    # a dictionary
    data = json.load(f)
    for i in data['hostdetails']:
        hostname = i['hostname']
        port = i['port']
        check_it_out(hostname,port)
        # The email body for recipients with non-HTML email clients.
    print(count)
    if count > 0 :
        html="""
        <style>
            table {
            font-family: arial, sans-serif;
            border-collapse: collapse;
            width: 100%;
            }

            td, th {
            border: 1px solid #dddddd;
            text-align: left;
            padding: 8px;
            }
            # td{
            # background-color:#030303;
             # }

            tr:nth-child(even) {
            background-color: #dddddd;
            }
        </style>        
        """
        # The HTML body of the email.
        BODY_HTML = "<html><head>"+html+"</head><body><body><h1> Cerificates Going to  Expire in next " + str(left_days) +  " Days</h1><p><h3>No. of Certificates Going To Expire: " + str(expired) + "<h3><br>Please find the details below<br> <table width='600' cellpadding='0' cellspacing='0' align='center'> <tr><th>S.No</th><th>Host name</th><th> Peer name</th> <th> Common name </th> <th> SAN </th> <th> Start date </th><th> End date </th><th> Status </th></tr>"+msg+"</table></p></body></body></html>"

        # The character encoding for the email.
        CHARSET = "UTF-8"

        # Create a new SES resource and specify a region.
        client = boto3.client('ses',region_name=AWS_REGION)

        # Try to send the email.
        try:
            #Provide the contents of the email.
            response = client.send_email(
                Destination={
                    'ToAddresses': [
                        RECIPIENT,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': BODY_HTML,
                        },
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': SUBJECT,
                    },
                },
                Source=SENDER,
                # If you are not using a configuration set, comment or delete the
                # following line
            #ConfigurationSetName=CONFIGURATION_SET,
            )
        # Display an error if something goes wrong.	
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['MessageId'])
        # Closing file
        f.close()
        #with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        #    for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
        #        print_basic_info(hostinfo)    

