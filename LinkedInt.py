# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction


#!/usr/bin/python

import sys
import re
import time
import requests
import subprocess
import json
import argparse
import cookielib
import ConfigParser
import os
import urllib
import math
import urllib2
import string
from bs4 import BeautifulSoup
from thready import threaded

#reload(sys)
#sys.setdefaultencoding('utf-8')

""" Setup Argument Parameters """
parser = argparse.ArgumentParser(description='Discovery LinkedIn')
parser.add_argument('-u', '--keywords', help='Keywords to search')
parser.add_argument('-o', '--output', help='Output file (do not include extentions)')
parser.add_argument('-i', '--companyid', help="companyID")
parser.add_argument('-d', '--domain', help="email domain")
parser.add_argument('-f', '--format', help="email format (full,firstlast,firstmlast,flast,firstl,first.last,fmlast,lastfirst)")
args = parser.parse_args()
config = ConfigParser.RawConfigParser()
config.read('LinkedInt.cfg')
api_key = config.get('API_KEYS', 'hunter')
username = config.get('CREDS', 'linkedin_username')
password = config.get('CREDS', 'linkedin_password')

def login():
	cookie_filename = "cookies.txt"
	cookiejar = cookielib.MozillaCookieJar(cookie_filename)
	opener = urllib2.build_opener(urllib2.HTTPRedirectHandler(),urllib2.HTTPHandler(debuglevel=0),urllib2.HTTPSHandler(debuglevel=0),urllib2.HTTPCookieProcessor(cookiejar))
	page = loadPage(opener, "https://www.linkedin.com/")
	parse = BeautifulSoup(page, "html.parser")

	csrf = parse.find(id="loginCsrfParam-login")['value']
	
	login_data = urllib.urlencode({'session_key': username, 'session_password': password, 'loginCsrfParam': csrf})
	page = loadPage(opener,"https://www.linkedin.com/uas/login-submit", login_data)
	
	parse = BeautifulSoup(page, "html.parser")
	cookie = ""
	
	try:
		cookie = cookiejar._cookies['.www.linkedin.com']['/']['li_at'].value
	except:
                print "[!] Cannot log in"
		sys.exit(0)
	
	cookiejar.save()
	os.remove(cookie_filename)
	return cookie

def loadPage(client, url, data=None):
	try:
		response = client.open(url)
	except:
		print "[!] Cannot load main LinkedIn page"
	try:
		if data is not None:
			response = client.open(url, data)
		else:
			response = client.open(url)
		return ''.join(response.readlines())
	except:
		sys.exit(0)

# convert "lastname, JUNK, ..." to "lastname"
# or "lastname JUNK .."
def sanitize_name(name):
    new_name = name
    if name.find(", ") > 0:
        new_name = name[:name.find(", ")]
    match = re.search("(?:[A-Za-z](?:[a-z]+|[ ]|[']))+( +[A-Z]{2,}.*)", new_name)
    if match:
        return new_name[:match.start(1)]
    else:
        return new_name

def get_search():

    body = ""
    csv = []
    css = """<style>
    #employees {
        font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        border-collapse: collapse;
        width: 100%;
    }

    #employees td, #employees th {
        border: 1px solid #ddd;
        padding: 8px;
    }

    #employees tr:nth-child(even){background-color: #f2f2f2;}

    #employees tr:hover {background-color: #ddd;}

    #employees th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #4CAF50;
        color: white;
    }
    </style>

    """

    header = """<center><table id=\"employees\">
             <tr>
             <th>Photo</th>
             <th>Name</th>
             <th>Possible Email:</th>
             <th>Job</th>
             <th>Location</th>
             </tr>
             """

    # Do we want to automatically get the company ID?

    if bCompany:
	    if bAuto:
	        # Automatic
	        # Grab from the URL 
	        companyID = 0
	        url = "https://www.linkedin.com/voyager/api/typeahead/hits?q=blended&query=%s" % search
	        headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
	        cookies['JSESSIONID'] = 'ajax:0397788525211216808'
	        r = requests.get(url, cookies=cookies, headers=headers)
	        content = json.loads(r.text)
	        firstID = 0
	        for i in range(0,len(content['elements'])):
	        	try:
	        		companyID = content['elements'][i]['hitInfo']['com.linkedin.voyager.typeahead.TypeaheadCompany']['id']
	        		if firstID == 0:
	        			firstID = companyID
	        		print "[Notice] Found company ID: %s" % companyID
	        	except:
	        		continue
	        companyID = firstID
	        if companyID == 0:
	        	print "[WARNING] No valid company ID found in auto, please restart and find your own"
	    else:
	        # Don't auto, use the specified ID
	        companyID = bSpecific

	    print
	    
	    print "[*] Using company ID: %s" % companyID

	# Fetch the initial page to get results/page counts
    if bCompany == False:
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=0" % search
    else:
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&keywords=%s&origin=OTHER&q=guided&start=0" % (companyID, search)
    
    print url
    
    headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
    cookies['JSESSIONID'] = 'ajax:0397788525211216808'
    #print url
    r = requests.get(url, cookies=cookies, headers=headers)
    content = json.loads(r.text)
    data_total = content['elements'][0]['total']

    # Calculate pages off final results at 40 results/page
    pages = data_total / 40

    if pages == 0:
    	pages = 1

    if data_total % 40 == 0:
        # Becuase we count 0... Subtract a page if there are no left over results on the last page
        pages = pages - 1 

    if pages == 0: 
    	print "[!] Try to use quotes in the search name"
    	sys.exit(0)
    
    print "[*] %i Results Found" % data_total
    if data_total > 1000:
        pages = 25
        print "[*] LinkedIn only allows 1000 results. Refine keywords to capture all data"
    print "[*] Fetching %i Pages" % pages
    print

    for p in range(pages):
        # Request results for each page using the start offset
        if bCompany == False:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=%i" % (search, p*40)
        else:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&keywords=%s&origin=OTHER&q=guided&start=%i" % (companyID, search, p*40)
        #print url
        r = requests.get(url, cookies=cookies, headers=headers)
        content = r.text.encode('UTF-8')
        content = json.loads(content)
        print "[*] Fetching page %i with %i results" % ((p),len(content['elements'][0]['elements']))
        for c in content['elements'][0]['elements']:
            if 'com.linkedin.voyager.search.SearchProfile' in c['hitInfo'] and c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['headless'] == False:
                try:
                    data_industry = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['industry']
                except:
                    data_industry = ""    
                data_firstname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['firstName']
                data_lastname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['lastName']
                data_slug = "https://www.linkedin.com/in/%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['publicIdentifier']
                data_occupation = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['occupation']
                data_location = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['location']
                try:
                    data_picture = "%s%s" % (c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['rootUrl'],c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['artifacts'][2]['fileIdentifyingUrlPathSegment'])
                except:
                    print "[*] No picture found for %s %s, %s" % (data_firstname, data_lastname, data_occupation)
                    data_picture = ""

                #try to remove junk from lastname, clearly people on linkedin dont know what last name means?
                original_lastname = data_lastname
                data_lastname = sanitize_name(data_lastname)
                
                # incase the last name is multi part, we will split it down

                parts = data_lastname.split()

                name = data_firstname + " " + data_lastname
                fname = ""
                mname = ""
                lname = ""

                if len(parts) == 1:
                    fname = data_firstname
                    mname = '?'
                    lname = parts[0]
                elif len(parts) == 2:
                    fname = data_firstname
                    mname = parts[0]
                    lname = parts[1]
                elif len(parts) >= 3:
                    fname = data_firstname
                    lname = parts[0]
                else:
                    fname = data_firstname
                    lname = '?'

                fname = re.sub('[^A-Za-z]+', '', fname)
                mname = re.sub('[^A-Za-z]+', '', mname)
                lname = re.sub('[^A-Za-z]+', '', lname)

                if len(fname) == 0 or len(lname) == 0:
                    # invalid user, let's move on, this person has a weird name
                    continue

                    #come here

                if prefix == 'full':
                    user = '{}{}{}'.format(fname, mname, lname)
                if prefix == 'firstlast':
                    user = '{}{}'.format(fname, lname)
                if prefix == 'firstmlast':
                    if len(mname) == 0:
                        user = '{}{}{}'.format(fname, mname, lname)
                    else:
                        user = '{}{}{}'.format(fname, mname[0], lname)
                if prefix == 'flast':
                    user = '{}{}'.format(fname[0], lname)
                if prefix == 'firstl':
                    user = '{}{}'.format(fname,lname[0])
                if prefix == 'first.last':
                    user = '{}.{}'.format(fname, lname)
                if prefix == 'fmlast':
                    if len(mname) == 0:
                        user = '{}{}{}'.format(fname[0], mname, lname)
                    else:
                        user = '{}{}{}'.format(fname[0], mname[0], lname)
                if prefix == 'lastfirst':
                	user = '{}{}'.format(lname, fname)

                email = '{}@{}'.format(user, suffix)

                body += "<tr>" \
                    "<td><a href=\"%s\"><img src=\"%s\" width=200 height=200></a></td>" \
                    "<td><a href=\"%s\">%s</a></td>" \
                    "<td>%s</td>" \
                    "<td>%s</td>" \
                    "<td>%s</td>" \
                    "<a>" % (data_slug, data_picture, data_slug, name, email, data_occupation, data_location)
                
                

                csv.append( ('"%s","%s","%s","%s","%s", "%s"' % (data_firstname, original_lastname, name, email, data_occupation, data_location.replace(",",";")) ).encode("utf-8"))
                foot = "</table></center>"
                f = open('{}.html'.format(outfile), 'wb')
                f.write(css)
                f.write(header)
                f.write(body.encode("utf-8"))
                f.write(foot)
                f.close()
                f = open('{}.csv'.format(outfile), 'wb')
                f.writelines('\n'.join(csv))
                f.close()
            else:
                print "[!] Headless profile found. Skipping"
        print

def banner():
        with open('banner.txt', 'r') as f:
            data = f.read()

            print "\033[1;31m%s\033[0;0m" % data
            print "\033[1;34mProviding you with Linkedin Intelligence"
            print "\033[1;32mAuthor: Vincent Yiu (@vysec, @vysecurity)\033[0;0m"
            print "\033[1;32mOriginal version by @DisK0nn3cT\033[0;0m"

def authenticate():
    try:
    	a = login()
    	print a
        session = a
        if len(session) == 0:
            sys.exit("[!] Unable to login to LinkedIn.com")
        print "[*] Obtained new session: %s" % session
        cookies = dict(li_at=session)
    except Exception, e:
        sys.exit("[!] Could not authenticate to linkedin. %s" % e)
    return cookies

if __name__ == '__main__':
    banner()
    # Prompt user for data variables
    search = args.keywords if args.keywords!=None else raw_input("[*] Enter search Keywords (use quotes for more precise results)\n")
    print 
    outfile = args.output if args.output!=None else raw_input("[*] Enter filename for output (exclude file extension)\n")
    print

    if not args.companyid:
        while True:
            bCompany = raw_input("[*] Filter by Company? (Y/N): \n")
            if bCompany.lower() == "y" or bCompany.lower() == "n":
                break
            else:
                print "[!] Incorrect choice"

        if bCompany.lower() == "y":
            bCompany = True
        else:
            bCompany = False

        bAuto = True
        bSpecific = 0
        prefix = ""
        suffix = ""

        print

        if bCompany:
    	    while True:
    	        bSpecific = raw_input("[*] Specify a Company ID (Provide ID or leave blank to automate): \n")
    	        if bSpecific != "":
    	            bAuto = False
    	            if bSpecific != 0:
    	                try:
    	                    int(bSpecific)
    	                    break
    	                except:
    	                    print "[!] Incorrect choice, the ID either has to be a number or blank"
    	                
    	            else:
    	                print "[!] Incorrect choice, the ID either has to be a number or blank"
    	        else:
    	            bAuto = True
    	            break
    else:
        bCompany = True
        bSpecific = int(args.companyid)
        bAuto = False

    print

    if not args.domain:
        while True:
            suffix = raw_input("[*] Enter e-mail domain suffix (eg. contoso.com): \n")
            suffix = suffix.lower()
            if "." in suffix:
                break
            else:
                print "[!] Incorrect e-mail? There's no dot"
    else:
        suffix = args.domain

    print

    if not args.format or not args.format in ["full","firstlast","firstmlast","flast","firstl","first.last","fmlast","lastfirst"]:
        while True:
            prefix = raw_input("[*] Select a prefix for e-mail generation (auto,full,firstlast,firstmlast,flast,firstl,first.last,fmlast,lastfirst): \n")
            prefix = prefix.lower()
            print
            if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "firstl" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
                break
            elif prefix == "auto":
                #if auto prefix then we want to use hunter IO to find it.
                print "[*] Automatically using Hunter IO to determine best Prefix"
                url = "https://hunter.io/trial/v2/domain-search?offset=0&domain=%s&format=json" % suffix
                r = requests.get(url)
                content = json.loads(r.text)
                if "status" in content:
                    print "[!] Rate limited by Hunter IO trial"
                    url = "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s" % (suffix, api_key)
                    #print url
                    r = requests.get(url)
                    content = json.loads(r.text)
                    if "status" in content:
                        print "[!] Rate limited by Hunter IO Key"
                        continue
                #print content
                prefix = content['data']['pattern']
                print "[!] %s" % prefix
                if prefix:
                    prefix = prefix.replace("{","").replace("}", "")
                    if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "firstl" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
                        print "[+] Found %s prefix" % prefix
                        break
                    else:
                        print "[!] Automatic prefix search failed, please insert a manual choice"
                        continue
                else:
                    print "[!] Automatic prefix search failed, please insert a manual choice"
                    continue
            else:
                print "[!] Incorrect choice, please select a value from (auto,full,firstlast,firstmlast,flast,firstl,first.last,fmlast)"
    else:
        prefix = args.format

    print 


    
    # URL Encode for the querystring
    search = urllib.quote_plus(search)
    cookies = authenticate()
  
    
    # Initialize Scraping
    get_search()

    print "[+] Complete"
