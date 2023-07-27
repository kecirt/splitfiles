#!/usr/local/bin/python3
import sys
import os.path
import pandas as pd
from pathlib import Path
from time import strftime
from termcolor import cprint
from splitfiles import make_new_directory
from draft_emails import authenticate
from writeemails import write_emails

default_file = "hornet_country_list.txt"
directory_path = os.path.dirname(os.path.realpath(__file__))
default_path = os.path.join(directory_path, default_file)
hornet_contents_filename = "hornet_contacts.csv"
default_path_hornet = os.path.join(directory_path, hornet_contents_filename)
country_code_file = "country_codes.csv"
cc_path = os.path.join(directory_path, country_code_file)


def read_xlsx(filename):
    """
    Read the xlsx file and return a dataframe
    """
    if(".csv") in filename:
        imported_data = pd.read_csv(filename, encoding='ISO-8859-1')
        #df = pd.DataFrame(imported_data)
        #print(imported_data)
        #print("Your File is a CSV : ")
    else:
        imported_data = pd.read_excel(filename)
        #df = pd.DataFrame(imported_data)
        #print(imported_data)
        #print("Your File is a Excel : " , df.dtypes)
    return imported_data


def get_valid_countries(filename=default_path):
    """
    Get the countries we have contacts of from a file
    ('hornet_country_list.txt')
    """
    with open(filename) as f:
        countries = f.readlines()
    return([x.strip() for x in countries])


def get_country_codes(filename=cc_path):
    """
    Get countries and their country codes.
    """
    return (pd.read_csv(cc_path))


def drop_entries_with_no_cc_value(dataframe):
    """
    Drop lines with no cc_value in dataset.
    """
    dataframe = dataframe.dropna(axis=0, subset=["source.geolocation.cc"])
    return dataframe


def get_unique_cc_values_in_dataframe(dataframe):
    """
    Get CC values in a dataset.
    """
    return (list(dataframe["source.geolocation.cc"].unique()))


def get_country_from_code(cc, country_codes_df):
    """
    Get the country name represented by a country code.
    """
    country = country_codes_df.loc[country_codes_df["Country Code"] ==
                                   cc, "Country"].iloc[0]
    return country


def get_countrylist_from_codelist(cc_list, country_codes_df):
    """
    Get the country name represented by a country code.
    """
    country_list = list()
    for cc in cc_list:
        try:
            country = get_country_from_code(cc, country_codes_df)
        except IndexError:
            continue
        country_list.append(country)
    return country_list


def get_countries(data_frame):
    """db_tablespace=''
    Determine unique countries in the data
    """
    valid_countries = get_valid_countries()
    if("Country Name" in data_frame.columns):
        countries_df = data_frame["Country Name"].unique()
        countries = (
            [country for country in valid_countries
             if country in countries_df])
    elif("source.geolocation.cc" in data_frame.columns):
        country_codes_df = get_country_codes()
        data_frame = drop_entries_with_no_cc_value(data_frame)
        country_codes_list = get_unique_cc_values_in_dataframe(data_frame)
        countries = get_countrylist_from_codelist(
            country_codes_list, country_codes_df)
    return set(countries)


def get_advisoryname(data_frame):
    """
    Determine what kind of data we are handling.
    Example: Web Attacks, Malware, Brutefroce
    """
    #return data_frame.iloc[0, -1]

    adv = "tpot"

    return adv


def get_file_path(file):
    """
    Get the path of the file being worked on.
    """
    try:
        return os.path.abspath(file)
    except IndexError:
        cprint("[!] Info: " + os.path.abspath(file) + " is empty.")


def determine_advisory(data_frame, document_path):
    """
    Determine what advisory we are working on.
    """
    if("ransomware" in document_path.lower()):
        adv = "ransomware"
    elif("bruteforce_" in document_path.lower()):
        adv = "bruteforce_global"
    elif("malware_" in document_path.lower()):
        adv = "malware_global"
    elif("webapp_" in document_path.lower()):
        adv = "webapp_global"
    elif("adb_global" in document_path.lower()):
        adv = "adb_attack_global"   
    elif("idsevents_global" in document_path.lower()):
        adv = "idsevents_global" 
    elif("tcpudp_global" in document_path.lower()):
        adv = "tcpudp_attacks_global" 
    elif("elastic_global" in document_path.lower()):
        adv = "elastic_global" 
    elif("cisco_global" in document_path.lower()):
        adv = "cisco_global" 
    elif("loginattempts_global" in document_path.lower()):
        adv = "loginattempts_global"
    elif("rdp_global" in document_path.lower()):
        adv = "rdp_global"     
    else:
        try:
            adv = get_advisoryname(data_frame)
            #print("\n" + adv)
        except IndexError:
            cprint("[!] Info: The specified file is probably empty.", "green")
            cprint("[!] Info: Exiting...", "green")
            exit(0)
    return adv


def determine_file_name(advisory, country):
    """
    Determine name of a files.
    """
    doc_date = strftime("%Y-%m-%d")
    advisory = advisory.split(" ")[0]
    doc_name = (doc_date + "_" + advisory.lower() +
                "-" + country.lower() + ".csv")
    return doc_name


def get_dataframe_needed(data_frame, document_path, country):
    """
    Get dataset with values you want to write to a file.
    """
    document_name = os.path.basename(document_path)
    if("ransomware" in str(document_name).lower()):
        df = data_frame.loc[data_frame["source.geolocation.cc"] == country]
    else:
        df = data_frame.loc[data_frame["Country Name"] == country]
    return(df)


def get_country_code_from_country(country):
    """
    Get country from country code.
    """
    country_code_df = get_country_codes()
    try:
        country_code = country_code_df.loc[country_code_df["Country"] ==
                                           country, "Country Code"].iloc[0]
    except IndexError:
        country_code = None
    return country_code


def write_one_file(country, data_frame, document_path, new_folder_path, adv):
    """
    Write one file depending on country.
    """
    if(not(pd.isnull(country))):
        original_country = country
        country = country.replace(" ", "")
        if("ransomware" in document_path):
            country_code = get_country_code_from_country(original_country)
            df = get_dataframe_needed(data_frame, document_path, country_code)
        else:
            df = get_dataframe_needed(
                data_frame, document_path, original_country)
        doc_name = determine_file_name(adv, original_country)
        df.to_csv(new_folder_path.joinpath(doc_name),
                  encoding="ISO-8859-1", index=False)


def write_csvs(data_frame, country_set, document_path):
    """
    Write multiple csvs based on the country under the 'Country Name' coloumn.
    """
    new_folder_path = make_new_directory(document_path)
    adv = determine_advisory(data_frame, document_path)
    for country in country_set:
        write_one_file(country, data_frame, document_path,
                       Path(new_folder_path), adv)
    cprint("\n[!] Successful!", "green")
    cprint("[!] Check out " + os.path.abspath(new_folder_path) +
           " for your files.\n", "green")
    return new_folder_path


def main():
    if(len(sys.argv) >= 2):
        for file in sys.argv[1:]:
            cprint("\n[!] Working with file: " +
                   str(os.path.basename(file)) + "\n", "green")

            try:
                file_path = get_file_path(file)
                df_data = read_xlsx(file_path)
                set_countries = get_countries(df_data)
                # write_csvs(df_data, set_countries, file_path)
                split_folder = write_csvs(df_data, set_countries, file_path)
                usr_account = authenticate()
                write_emails(user_account=usr_account,
                             contacts=default_path_hornet,
                             directory_path=split_folder)

            except IndexError:
                print
                cprint(
                    "[!!!] Error: Please specify a file: hornet_split.py <file>", "red")

            except FileNotFoundError:
                cprint("[!!!] Error: \' " + str(os.path.abspath(file)) +
                       " \'" +  " doesn\'t seem to exist.", "red")
    else:
        cprint("[!!!] Error: You did not specify a file.", "red")
        exit("Exiting...")


if __name__ == "__main__":
    main()
