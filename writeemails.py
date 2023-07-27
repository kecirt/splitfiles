import os
import pandas as pd
from termcolor import cprint
from exchangelib import Mailbox
from splitfiles import print_success_messages
from draft_emails import attach_ref, get_file_names
from draft_emails import determine_folder_in_ews, get_work_folder
from draft_emails import attach_file, enter_start_ref, populate_work_folder


def get_cert_contacts():
    """
    Get the contacts of the CERTs from a csv file.
    """
    hornet_contents_filename = 'hornet_contacts.csv'
    contacts = pd.read_csv(hornet_contents_filename)
    return contacts


def populate_contacts(contacts, cntry_list, files_list, count, item):
    """
    Populate the to, cc and bcc of an email.
    """
    country = files_list[count].split('-')[3].split('.')[0]
    country = country.replace(' ', '')
    index_of_cntry = cntry_list.index(country)
    to_list = []
    cc_list = []
    if(not(pd.isnull(contacts.values[index_of_cntry][2]))):
        cc_list.append(
            Mailbox(email_address=contacts.values[index_of_cntry][2]))
    to_list.append(
        Mailbox(email_address=contacts.values[index_of_cntry][1]))
    item.to_recipients = to_list
    item.cc_recipients = cc_list
    item.bcc_recipients = ['incidents@ke-cirt.go.ke', 'cirt@ca.go.ke']
    item.save(update_fields=['to_recipients',
                             'cc_recipients', 'bcc_recipients'])


def complete_email(directory_path, work_folder):
    """
    Enter recepients and attach advisories to emails.
    """
    start_ref = enter_start_ref()
    count = 0
    files_list = get_file_names(directory_path)
    contacts = get_cert_contacts()
    cntry_list = [x.lower().replace(' ', '') for x in contacts.country]
    for item in work_folder.all():
        populate_contacts(contacts, cntry_list, files_list, count, item)
        attach_ref(start_ref, item)
        attach_file(directory_path, files_list[count], item)
        count = count + 1
        start_ref = start_ref + 1
    cprint('[!] Info: Last reference number was ' +
           str(start_ref - 1), 'green')


def get_countries_in_folder(directory):
    """
    Get the countries in files in a split folder.
    """
    files_list = get_file_names(directory)
    countries = [country.split("-")[3].split(".")[0] for country in files_list]
    return countries


def write_emails(user_account, contacts, directory_path):
    """
    Actually write the emails.
    """
    directory_name = os.path.basename(directory_path)
    #print("\n Directory Path : " +directory_path)
    #print("\n Directory Name : " + directory_name)
    parent_folder = determine_folder_in_ews(directory_name, user_account)
    #print("\n Parent Folder" + parent_folder)
    work_folder = get_work_folder(parent_folder)
    populate_work_folder(parent_folder, directory_path)
    complete_email(directory_path, work_folder)
    print_success_messages()
