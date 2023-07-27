import sys
import os.path
import glob
import pandas as pd
import csv


def get_row_count(files):
	
	#count the number of rows in each csv file

	for csv_file  in files:

		open_csv_file = open(csv_file, encoding="ISO-8859-1")

		reader = csv.reader(open_csv_file)

		rows  = len(list(reader))

		print(str(os.path.basename(csv_file)) + " : " + str(rows-1) )	

def main():
	n = len(sys.argv)
	print("[!] Working with  :", len(sys.argv[1:]), " Folders")
	if (n >= 2):
			for file  in sys.argv[1:]:

				print("\n[!] Working with Folder :", str(os.path.basename(file)))

				#get the folder name 

				folder = str(os.path.abspath(file))

				#get the names of csv files inside the folder

				csv_files = glob.glob(str(folder) + '/*.csv')

				#count the number of rows 
				get_row_count(csv_files)


	else:
		cprint("[!!!] Error: You did not specify a folder.", "red")
		exit("Exiting...")


if __name__ == "__main__":
    main()