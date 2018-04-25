#!/usr/bin/python

import csv
import os, sys, json
import investigate
import fileinput
from time import sleep
from csv import DictReader
from datetime import datetime

# Created by Andrew Angrisani
# A ton of help provided by: Jan Dembowski, Thomas Wood & Ed Dembowski
#
# Created to parse BlueCoat Proxy Processed Access Logs, and provide any malicious domains allowed or marked as unknown by BlueCoat
#

# Investigate API key
api_key = ''
# Investigate API Key + Investigate Module
inv = investigate.Investigate(api_key)
# Needed to track time to completion
start = datetime.now()

if not os.path.exists("logs"):
    os.makedirs("logs")

# Needed when parsing the logs for Investigate query
def slice(l, n):
    n = max(1, n)
    return [l[i:i + n] for i in range(0, len(l), n)]

print("Welcome to the BlueCoat Proxy Parsing Script!")
print("Only to be used for the processed Access Logs grabbed via syslog")

# Ask for the input filename
log_file = raw_input('Enter the filename & extension for processing: ')

print ('\n')

# Ask what columns contain Web.dest and Web.action
print ("Please designate the columns for the following headers...")
print ("A=1 / B=2 / C=3, etc...")
destcol = raw_input('Enter the column number for Web.dest: ')
actcol = raw_input('Enter the column number for Web.action: ')

# Cut out superfluous columns
# -f$,$ designates the columns ... Column D & F will be cut out, which are Web.dest & Web.action
print("Creating separate file with Web.dest = %s & Web.action = %s columns only..." % (destcol, actcol))

# Cuts out the Web.dest and Web.action columns to reduce the overall filesize
os.system("cut -f%s,%s -d, %s  > logs/cutdomains.csv" % (destcol, actcol, log_file))
#
lines_seen = set() # holds lines already seen
outfile = open('logs/sortdomains.csv', "w")
for line in open('logs/cutdomains.csv', "r"):
    if line not in lines_seen: # not a duplicate
        outfile.write(line)
        lines_seen.add(line)
outfile.close()

processed_file = 'logs/sortdomains.csv'

# Providing synopisis for first section; also providing error check spot on terminal
print ('\n')
print ("Parsing %s and looking for Allowed & Unknown domains only..." % processed_file)
print ('\n')

# designate the file to be parsed
input_file = open(processed_file,"r")

# Only interested in the Web.action and Web.dest columns
i = ["Web.action","Web.dest"]
reader = csv.DictReader(input_file, delimiter=',')

trb = 0 # Total Rows that are Blocked
tra = 0 # Total Rows that are Allowed
adf = []

# Count all the rows that match the specific string [Allowed/Blocked/Unknown]
# Append matched allowed / unknown domain to lists for Investigate query
for row in reader:
    if row['Web.action'] == "Allowed" or row['Web.action'] == "configuration_error" or row['Web.action'] == "authentication_failed" or row['Web.action'] == "content_filter_denied" or row['Web.action'] == "invalid_request" or row['Web.action'] == "tcp_error" or row['Web.action'] == "content_encoding_error":
        tra += 1
        adf.append(row['Web.dest'])
    elif row['Web.action'] == "blocked":
        trb += 1

# Total rows for the document
all = tra+trb

print adf

# Print Statistics for quick viewing
print ("Total Allowed Domains: %s" % tra)
print ("Total Blocked Domains: %s" % trb)
print ("Total Domains: %s" % all)

# Write above stats to file for later use
stats = open("statistics.txt", "w")
stats.write("Total Allowed Domains: %s" % tra + '\n')
stats.write("Total Blocked Domains: %s" % trb + '\n')
stats.write("Total Domains: %s" % all + '\n')

print ('\n')
print ("Statistics and domains gathered... Moving on to Investigate Query...")
print ('\n')

print ('\n')
print ("Querying Investigate for Allowed Domains list...")

# ***
# BEGIN ALLOWED DOMAINS LIST PARSE
# ***

adout = open("logs/allowed_output.txt", "w+")

# Initialize vars
i=0
aof = open("allowed_malicious.csv", "w+")
aof.write("Domains" + ',' + "Malicious_Tag" + '\n')

# How many chunks do we need?
size = len(adf)
chunks = size / 1000
if chunks < 1:
    chunks = 1
slices=slice(adf,1000)

print slices
print ("Total Chunks: %s" % chunks)

for chunk in range(0, chunks):
    # Call to Investigate bulk endpoint
    results = inv.categorization(slices[chunk], labels=True)
    # save the results
    adout.write(json.dumps(results, sort_keys=True ,indent=4, separators=(',', ': ')))
    for key in results.keys():
        for item in results[key]:
            names=results[key][item]
            if names == [u'Malware'] or names == [u'Botnet'] or names == [u'Phishing']:
                print key
                print names
                sca = str(key) + ',' + str(names) + '\n'
                aof.write(sca)

aof.close()
adout.close()

print ('\n')
print ("Allowed Domains Completed!")
print ("Parsing of file is completed...")
print ('\n')

# Adding total malicious count from both files to stats file
input_allowed_file = open("allowed_malicious.csv","r")
i = ["Domains","Malicious_Tag"]
readera = csv.DictReader(input_allowed_file, delimiter=',')

total_a_mal = 0
total_a_bot = 0
total_a_phi = 0

for row in readera:
    if row["Malicious_Tag"] == "[u'Malware']":
        total_a_mal += 1
    elif row["Malicious_Tag"] == "[u'Botnet']":
        total_a_bot += 1
    elif row["Malicious_Tag"] == "[u'Phishing']":
        total_a_phi +=1

total_a_all = total_a_mal + total_a_bot + total_a_phi

# Write breakdown of malicious domains found within Allowed & Unknown domain lists
stats.write('\n')
stats.write("Allowed Malicious Domains Breakdown" + '\n')
stats.write("Total Malware Domains: %s" % total_a_mal + '\n')
stats.write("Total Botnet Domains: %s" % total_a_bot + '\n')
stats.write("Total Phishing Domains: %s" % total_a_phi + '\n')
stats.write("Total: %s" % total_a_all + '\n')

print ("Total Time:")
ToTime = datetime.now()-start
print ToTime
stats.write('\n')
stats.write("Total Time: %s" % ToTime)
stats.close()