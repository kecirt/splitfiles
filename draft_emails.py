import os.path
import sys
import getpass
import pandas as pd
from time import strftime
from termcolor import cprint
from exchangelib import Configuration
from exchangelib import Credentials, Account
from exchangelib import FileAttachment, HTMLBody

isp_file_name = "isp_contacts.csv"
script_path = os.path.realpath(__file__)
directory = os.path.dirname(script_path)
contacts_path = os.path.join(directory, isp_file_name)

# Dictionary for ISPs
isp_dict = {
    "accesskenya": "Internet Solutions (Access Kenya) Ltd",
    "icta": "ICT Authority of Kenya", "angani": "Angani",
    "jtl": "Jamii Telecom Ltd",
    "kenet": "Kenya Education Network (KENET)", "telkom": "Telkom Kenya Ltd",
    "wananchi": "Wananchi Ltd", "safaricom": "Safaricom Ltd",
    "seacom": "Seacom", "mawingu": "Mawingu Network",
    "simbanet": "Simbanet Ltd",
    "mtn": "MTN Business", "xtranet": "Xtranet Ltd",
    "iwayafrica": "iWayAfrica/Africa Online Kenya",
    "nodeafrica": "Node Africa", "kenyaweb": "Kenya Web Ltd",
    "wananchi": "Wananchi Ltd", "hirani": "Hirani Telecommunication ltd",
    "unwired": "Unwired Communications Limited", "afriq": "Afriq Network Solutions Limited",
    "dobie": "DT Dobie Kenya Ltd", "frontier": "Frontier Optical Networks Ltd",
    "strathmore": "Strathmore University", "eclectics": "Eclectics International Ltd",
    "geonet": "Geonet Communications Ltd",
    "craft": "Craft Silicon Ltd", "sawasawa": "SawaSawa.com", "ilri": "International Livestock Research Institute",
    "mla": "Message Labs Africa LTD", "kpo": "Kenya Post Office Savings Bank",
    "webrunner": "WebRunner Limited", "kpa": "Kenya Ports Authority"
}

# Dictionary of filenames to folder in analysis-cse draft
ews_dict = {
    "andromeda": "Andromeda", "necurs": "Necurs", "pykspa": "Pykspa","suppobox": "Suppobox",
    "emotet" : "Emotet", "bedep": "Bedep", "nymaim": "Nymaim", "m0yv": "M0yv", "gamarue": "Gamarue",
    "tinba": "Tinba", "qsnatch": "QSnatch", "zeus" : "Zeus", "matsnu" : "Matsnu", "ranbyus" : "Ranbyus",
    "isakmp": "ISAKMP", "ssdp": "SSDP",
    "telnet": "Telnet v4", "portmapper": "Portmapper",
    "scan_poodle": "SSLv3/Poodle", "memcached": "Memcached",
    "ms-sql": "MS-SQL", "ldap": "LDAP UDP", "smb": "SMB",
    "scan_freak": "SSL/TLS (Freak)", "blacklist": "Blacklist",
    "blocklist-kenya": "Blacklisted IPs","blocklist-kenya": "Blocklist",
    "botnet_drone": "Botnet Drone", "mdns": "mDNS",
    "mongodb": "MongoDB", "netbios": "NetBIOS", "rdp": "RDP",
    "snmp": "SNMP", "tftp": "Open TFTP", "nat_pmp": "NAT-PMP",
    "scan_dns": "DNS Open Resolver", "scan_cwmp": "Open-CWMP",
    "scan_vnc": "Accessible VNC service",
    "scan_ntp-": "NTP-version", "scan_ntpmonitor": "NTP-monitor",
    "scan_ftp": "Accessible FTP", "scan_adb": "Android debug bridge",
    "scan_elasticsearch": "Elasticsearch", "darknet": "Darknet",
    "ddos_amplification": "Amplification DDoS Victim",
    "scan_rsync": "Accessible rsync Service",
    "cisco_smart": "Accessible Cisco Smart Install",
    "scan_xdmcp": "Accessible XDMCP Service", "scan_ipmi": "IPMI",
    "scan_qotd": "QOTD",
    "hp_http_scan": "HTTP Scanners", "scan_ics": "ICS Scanners",
    "ubiquiti": "Open-Ubiquiti", "chargen": "Open-Chargen",
    "compromised_website": "Compromised-Website", "phishing": "Phishing",
    "http_vulnerable": "HTTP Vulnerable", "web-": "Web App",
    "bruteforce-": "Bruteforce", "malware": "Malware",
    "ransomware": "Ransomware", "scan_redis": "Open-Redis",
    "scan_ard": "ARD", "scan_afp": "AFP",
    "db2": "Open DB2", "ldap_tcp": "LDAP TCP", "intel_darknet": "Darknet",
    "intel_ssh": "SSH","ipp":"Open IPP", "scan_coap": "Accessible CoAP",
    "scan_mqtt": "Open MQTT", "scan_hadoop": "Accessible Hadoop", "scan_radmin": "Exposed Radmin Service",
    "scan_exchange": "Vulnerable Exchange Server", "scan_rdpeudp" : "Accessible MS-RDPEUDP",
    "event4_sinkhole": "Sinkholev4 HTTP Events", "event6_sinkhole": "Sinkholev6 HTTP Events", "honeypot_brute": "Honeypot Brute Force",
    "honeypot_ddos": "Honeypot DDoS", "honeypot_http_scan": "Honeypot HTTP Scanners",
    "honeypot_darknet": "Honeypot Darknet", "scan_smtp": "SMTP", "microsoft_sinkhole_http": "Microsoft Sinkhole HTTP",
    "bruteforce_kenya": "Brute Force","malware_kenya" : "Malware", "webapp_kenya" : "Web App",
    "bruteforce_global": "Brute Force","malware_global" : "Malware", "webapp_global" : "Web App",
    "sandbox_url": "Sandbox URL", "device_id": "Device IDv4", "ip_spoofer": "IP Spoofer", "vulnerable_log4j_server": "Vulnerable Log4j Server",
    "scan6_telnet": "Telnet v6", "device_idv6": "Device IDv6", "scan_amqp": "AMQP", "adb_kenya" : "Android Debug Bridge", "adb_global" : "Android Debug Bridge", "cisco_global": "Cisco",
    "elastic_global": "Elastic", "idsevents_global": "IDS Events", "idsevents_kenya": "IDS Events", "loginattempts_global": "Login Attempts", "tcpudp_global": "TCU/UDP Attacks", 
    "tcpudp_kenya": "TCU/UDP Attacks", "scan6_ssl": "Accessible SSL IPv6", "scan6_ssh": "Accessible SSH IPv6", "scan6_smtp": "Accessible SMTP IPv6", "scan_http6": "Accessible HTTP IPv6",
    "scan_ssl": "Accessible SSL IPv4", "scan_ssh": "Accessible SSH IPv4", "sinkhole_dns": "Sinkhole DNS Events", "scan_quic": "Accessible QUIC", "scan_mysql": "Accessible MySQL",
    "scan6_mysql": "Accessible MySQL IPv6", "scan_kubernetes": "Accessible Kubernetes", "scan_epmd": "Accessible Erlang Port", "scan_dvr": "Open DVR DHCPDiscover",
    "scan_ddos": "Vulnerable DDoS Middlebox", "scan_socks": "Accessible SOCKS", "rdp_global": "RDP", "rdp_kenya": "RDP", "scan_http4": "Accessible HTTP IPv4", "scan_ftp6": "Accessible FTP IPv6",
    "scan_postgres": "Postgres", "scan6_postgres": "Postgres IPv6", "scan_couchdb": "Couchdb", "scan6_ntp": "NTP-version IPv6", "scan6_ntpmonitor": "NTP-monitor IPv6", "population_bgp": "Accessible BGP",
    "population6_bgp": "Accessible BGP IPv6", "population_http_proxy": "Accessible HTTP Proxy", "population6_http_proxy": "Accessible HTTP Proxy IPv6", "population_msmq": "Accessible MSMQ",
    "population6_msmq": "Accessible MSMQ IPv6", "scan_sip": "Accessible SIP", "scan_slp": "Accessible SLP", "scan6_slp": "Accessible SLP IPv6", "scan_stun": "Accessible STUN", "scan6_stun": "Accessible STUN IPv6",
    "scan_ws_discovery": "Accessible WS-Discovery", "scan6_dns": "DNS Open Resolver IPv6", "scan6_ssl_poodle": "SSL POODLE IPv6", "scan6_snmp": "SNMP IPv6", "scan6_http_vulnerable": "HTTP Vulnerable IPv6"
    }


def authenticate():
    """
    Authenticate into chosen mail
    """
    e_address = "enter your mail address"
    paswd = getpass.getpass(prompt="Enter password for chosen mail address:") #edit it to read chosed mail
    user_credentials = Credentials(e_address, paswd)
    config = Configuration(server="enter your mail server", #for example it can be mail.example.com
                           credentials=user_credentials)
    user_account = Account(primary_smtp_address=e_address, config=config,
                           credentials=user_credentials, autodiscover=False)
    return user_account


def get_file_names(directory_path):
    """
    Get the names of files in the directory in a list.
    """
    return (os.listdir(directory_path))


def get_number_of_files(directory_path):
    """
    Get the number of files created by spliting.
    """
    return (len(os.listdir(directory_path)))


def attach_ref(ref_num, message_item):
    """
    Attach subject/reference number
    """
    subject_text = "National KE-CIRT/CC Cyber Incident Advisory " \
        "- Ref:National KE-CIRT-"
    message_item.subject = subject_text + \
        strftime("%d-%m-%Y") + "-" + str(ref_num).rjust(2, "0")
    message_item.save()


def get_isp_contacts(contacts_file=contacts_path):
    """
    Get the ISP contacts from a file.
    """
    contacts = pd.read_csv(contacts_file)
    return contacts


def change_isp(message_item, isp_n):
    """
    Insert ISP on body of email.
    Email body must have placeholder "isp_name"
    """
    template_body = message_item.body
    temp_body_final = template_body.replace("isp_name", isp_dict[isp_n])
    message_item.body = HTMLBody(temp_body_final)
    message_item.save(update_fields=["body"])


def attach_contacts(contacts_df, isp_name, message_item):
    """
    Add "'"to"'", "'"cc"'" and "'"bcc"'" values to a message item.
    """
    print(".\n..\n...")
    print(isp_name)
    to_list = contacts_df.loc[contacts_df.Body ==
                              isp_name, "Email"].values[0].split("&")
    cc = contacts_df.loc[contacts_df.Body ==
                         isp_name, "Personnel Email"].values[0]
    cc_list = []
    if(not(pd.isnull(cc))):
        cc_list = contacts_df.loc[contacts_df.Body ==
                                  isp_name, "Personnel Email"].values[0].split("&")
    bcc_list = ["incidents@ke-cirt.go.ke"]
    message_item.to_recipients = to_list
    message_item.cc_recipients = cc_list
    message_item.bcc_recipients = bcc_list
    message_item.save(
        update_fields=["to_recipients", "cc_recipients", "bcc_recipients"])


def get_p_folder(folder_name, usr_account, given_folder):
    """
    Get folder with main template
    """
    for key in ews_dict:
        if key in folder_name:
            p_folder = given_folder / ews_dict[key]
    return p_folder


def determine_folder_in_ews(folder_name, usr_account, draft_choice):
    """
    Determine which folder in drafts the emails will go to.
    """
    if(draft_choice == 1):
        certbund_folder = usr_account.drafts / "CertBund"
        hornet_kenya_folder = usr_account.drafts / "Honeypot Kenya"
        hornet_global_folder = usr_account.drafts / "Honeypot Global"
        #hornet_folder = usr_account.drafts / "Hornet"
        intelmq_folder = usr_account.drafts / "IntelMQ"
        shadowserver_folder = usr_account.drafts / "Shadowserver"
        folder_name = os.path.abspath(folder_name)
        f_basename = os.path.basename(folder_name).lower()
        is_certbund =(
            "andromeda" in f_basename or
            "pykspa" in f_basename or
            "necurs" in f_basename or
            "suppobox" in f_basename or
            "emotet" in f_basename or
            "bedep" in f_basename or
            "nymaim" in f_basename or
            "qsnatch" in f_basename or
            "tinba" in f_basename or
            "zeus" in f_basename or
            "matsnu" in f_basename or
            "ranbyus" in f_basename or 
            "m0yv" in f_basename or 
            "gamarue" in f_basename
        )
        is_hornet_kenya = (
            "bruteforce_kenya" in f_basename or
            "malware_kenya" in f_basename or
            "webapp_kenya" in f_basename or
            "adbhoney_kenya" in f_basename or 
            "tcpudp_kenya" in f_basename or 
            "idsevents_kenya" in f_basename or 
            "rdp_kenya" in f_basename
        )
        is_hornet_global = (
            "webapp_global" in f_basename or
            "bruteforce_global" in f_basename or
            "malware_global" in f_basename or
            "adb_global" in f_basename or
            "cisco_global" in f_basename or
            "elastic_global" in f_basename or 
            "loginattempts_global" in f_basename or 
            "idsevents_global" in f_basename or 
            "tcpudp_global" in f_basename or 
            "rdp_global" in f_basename
        )
        is_intelmq = (
            "blacklist" in f_basename or
            "phishing" in f_basename or
            "ransomware" in f_basename or
            "intel_darknet" in f_basename or
            "intel_ssh" in f_basename
        )
        # if("andromeda" in f_basename):
        #     p_folder = usr_account.drafts / "Andromeda"
        # elif("necurs" in f_basename):
        #     p_folder = usr_account.drafts / "Necurs"
        # elif("pykspa" in f_basename):
        #     p_folder = usr_account.drafts / "Pykspa"
        if(is_certbund):
            p_folder = get_p_folder(f_basename, usr_account, certbund_folder)
        elif(is_hornet_kenya):
            p_folder = get_p_folder(f_basename, usr_account, hornet_kenya_folder)
        elif(is_hornet_global):
            p_folder = get_p_folder(f_basename, usr_account, hornet_global_folder)
        elif(is_intelmq):
            p_folder = get_p_folder(f_basename, usr_account, intelmq_folder)
        else:
            p_folder = get_p_folder(f_basename, usr_account, shadowserver_folder)
        return p_folder
    else:
        isps = isp_dict.keys()
        folder_name = os.path.abspath(folder_name)
        f_basename = os.path.basename(folder_name).lower()
        shadowserver_folder = usr_account.drafts / "Shadowserver"
        for isp in isps:
            if(isp in f_basename):
                p_folder = shadowserver_folder / isp_dict[isp]
        return p_folder


def get_work_folder(p_folder):
    """
    Get working folder.
    """
    w_folder = p_folder / "work"
    return (w_folder)


def delete_emails(folder):
    """
    Delete all emails in the email folder
    """
    folder.all().delete()


def get_isps_in_folder(folder):
    """
    Get the isps in files in a split folder.
    """
    files_list = get_file_names(folder)
    folder = str(os.path.basename(folder)).lower()
    if("nat_pmp" in folder or "scan_ms-sql" in folder):
        isp_list = [isp.split("-")[5].split(".")[0] for isp in files_list]
    elif("ransomware" in folder):
        isp_list = [isp.split("-")[3].split(".")[0] for isp in files_list]
    else:
        isp_list = [isp.split("-")[4].split(".")[0] for isp in files_list]
    return isp_list


def get_isp_from_filename(filename):
    """
    Get isp in a filename
    """
    if("pmp" in filename or "ms-sql" in filename):
        isp_n = filename.split("-")[5].split(".")[0]
    elif("ransomware" in filename):
        isp_n = filename.split("-")[3].split(".")[0]
    else:
        isp_n = filename.split("-")[4].split(".")[0]
    return isp_n


def get_const_isp(isp_n):
    """
    Get absolute isp of safaricom and accesskenya.
    """
    if(isp_n == "safaricom(1)" or isp_n == "safaricom(2)"):
        isp_n = "safaricom"
    if(isp_n == "is"):
        isp_n = "accesskenya"
    return isp_n


def copy_draft(parent_folder, w_folder):
    """
    Make a copy of the main draft in the work folder
    """
    for item in parent_folder.all():
        item.copy(w_folder)
        item.save()


def populate_work_folder(parent_folder, d_path):
    """
    Copy the main template to "'"work"'" folder as many times as files in the
    directory specified.
    """
    w_folder = get_work_folder(parent_folder)
    delete_emails(w_folder)
    duplicate_list = list()  # if both files of accesskenya and safaricom exist
    same_isp = 0  # to keep track of access/is and safaricom(1)/(2)
    no_of_files = get_number_of_files(d_path)
    d_path_s = str(os.path.basename(d_path))
    if("webapp_global" in d_path_s or
        "bruteforce_global"in d_path_s or
        "malware_global" in d_path_s or
        "adb_global" in d_path_s or
        "tcpudp_global" in d_path_s or
        "cisco_global" in d_path_s or
        "ransomware" in d_path_s or 
        "elastic_global" in d_path_s or 
        "idsevents_global" in d_path_s or
        "loginattempts_global" in d_path_s or 
        "rdp_global" in d_path_s        

       ):
        pass
    else:
        isp_list = get_isps_in_folder(d_path)
        if("safaricom(1)" in isp_list and
           "safaricom(2)" in isp_list
           ):
            same_isp = same_isp + 1
            duplicate_list.append("safaricom")
        if("accesskenya" in isp_list and
            "is" in isp_list
           ):
            same_isp = same_isp + 1
            duplicate_list.append("accesskenya")
        no_of_files = no_of_files - same_isp
    count = 0
    while(count < no_of_files):
        copy_draft(parent_folder, w_folder)
        count = count + 1
    print(str(no_of_files) + " emails have been made in the work folder.")
    return duplicate_list


def enter_start_ref():
    """
    Enter the first reference number you are working with.
    """
    no = False
    start_ref = 0
    while(not(no)):
        try:
            start_ref = int(input("Enter the starting ref: "))
        except ValueError:
            cprint("[!!] Warning: You didn\'t enter a digit.", "yellow")
        else:
            no = True
    return start_ref


def complete_emials(d_path, work_folder, duplicate_list):
    """
    1. Attach files from a folder to the emails copied \
    to the work folder attach_file().
    2. Change contacts of emails with the attach_contacts() function.
    3. Change subject of email(reference number) attach_ref()
    4. Enter isp name to body of the email change_isp().
    """
    dup_file_list = list()
    start_ref = enter_start_ref()
    count = 0
    files_list = get_file_names(d_path)
    for item in work_folder.all():
        if(not(files_list[count] in dup_file_list)):
            isp_n = get_isp_from_filename(files_list[count])
            isp_n_cons = get_const_isp(isp_n)
            change_isp(item, isp_n_cons)
            attach_contacts(get_isp_contacts(), isp_n_cons, item)
            attach_ref(start_ref, item)
            attach_file(d_path, files_list[count], item)
            dup_file_list = attach_second_file(duplicate_list, files_list,
                                               count, isp_n, dup_file_list,
                                               d_path, item)
            count = count + 1
        else:
            isp_n = get_isp_from_filename(files_list[count + 1])
            isp_n_cons = get_const_isp(isp_n)
            change_isp(item, isp_n_cons)
            attach_contacts(get_isp_contacts(), isp_n_cons, item)
            attach_ref(start_ref, item)
            attach_file(d_path, files_list[count + 1], item)
            count = count + 2
        start_ref = start_ref + 1
    cprint("[!] Info: The emails have been created.", "green")
    cprint("[!] Info: Last reference number was " +
           str(start_ref - 1), "green")


def attach_second_file(d_list, f_list, count, isp_n, dup_f_list, d_path, item):
    """
    Attach files for Safaricom(2) or IS if they exist.
    """
    if("safaricom" in d_list and
        "safaricom" in f_list[count]
       ):
        for f in f_list:
            if("safaricom(2)" in f and
                isp_n == "safaricom(1)"
               ):
                index_of_d = f_list.index(f)
                dup_f_list.append(f)
                attach_file(d_path, f_list[index_of_d], item)
    if("accesskenya" in d_list and
        "accesskenya" in f_list[count]
       ):
        for f in f_list:
            if("-is" in f):
                index_of_d = f_list.index(f)
                dup_f_list.append(f)
                attach_file(d_path, f_list[index_of_d], item)
    return dup_f_list


def attach_file(directory_path, file_name, message_item):
    """
    Attach a file to a meassage item.
    """
    with open(os.path.join(directory_path, file_name), "rb") as f:
        file_content = f.read()
    file = FileAttachment(name=file_name, content=file_content)
    message_item.attach(file)


def main():
    if(len(sys.argv) >= 2):
        usr_account = authenticate()
        for file in sys.argv[1:]:
            cprint("\n[!] Working with folder: " +
                   str(os.path.abspath(file)) + "\n", "green")
            if("workbooks" in file and os.path.isdir(file)):
                list_of_files = get_file_names(file)
                count = 0
                start_ref = enter_start_ref()
                for f in list_of_files:
                    isp = f.split("-")[3].split(".")[0]
                    try:
                        p_folder = determine_folder_in_ews(f, usr_account, 2)
                    except:
                        cprint("[!!!] Error: No folder for " +
                            isp + " in the drafts.", "red")
                        continue
                    w_folder = get_work_folder(p_folder)
                    delete_emails(w_folder)
                    copy_draft(p_folder, w_folder)
                    for item in w_folder.all():
                        change_isp(item, isp)
                        attach_contacts(get_isp_contacts(), isp, item)
                        attach_ref(start_ref, item)
                        attach_file(file, f, item)
                        count += 1
                        start_ref += 1
                cprint("[!] Info: Created " + str(count) + " emails.\nLast reference number: " + str(start_ref-1), "green")
            elif(os.path.isdir(file)):
                try:
                    p_folder = determine_folder_in_ews(file, usr_account, 1)
                    w_folder = get_work_folder(p_folder)
                    dupli = populate_work_folder(p_folder, file)
                    complete_emials(file, w_folder, dupli)
                except IndexError:
                    print(file)
                    print(dupli)
                    print(p_folder)
                    print(w_folder)
                    cprint("[!!!] Error: Please specify a valid folder", "red")
                except FileNotFoundError:
                    cprint("[!!!] Error: \'' " + str(os.path.abspath(file)) +
                           " \'" + " doesn\'t seem to exist.", "red")
                except UnicodeDecodeError:
                    cprint("[!!!] Error: You have not selected a folder.\n",
                           "red")
            else:
                cprint("[!!!] Error: " + str(os.path.abspath(file)) +
                       " is not a folder.", "red")
    else:
        cprint("[!!!] Error: You did not specify a folder.", "red")
        exit("Exiting...")


if __name__ == "__main__":
    main()
