#!/usr/bin/env python3
# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction

import sys
import re
import time
import requests
import subprocess
import json
import argparse
from urllib.parse import quote
import configparser
import os
import math
import string
from bs4 import BeautifulSoup
from thready import threaded

proxies = {
 "http": "http://127.0.0.1:8080",
 "https": "http://127.0.0.1:8080",
}

def info(msg):
    print("[+] " + msg)

def err(msg):
    print("[-] " + msg)

def login(username, password):
    #return cookie li_at
    #page = loadPage(opener, "https://www.linkedin.com/login")
    #login_data = urllib.parse.urlencode({'session_key': username, 'session_password': password, 'loginCsrfParam': csrf})
    headers = {
        'User-agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:81.0) Gecko/20100101 Firefox/81.0"
    }
    s = requests.Session() 
    r = s.get("https://www.linkedin.com/login", headers = headers)
    parse = BeautifulSoup(r.text, "html.parser")
    csrf = parse.find("input", {"name":"loginCsrfParam"}).get("value")
    login_data = f"session_key={quote(username)}&session_password={quote(password)}&loginCsrfParam={csrf}"
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    r = s.post("https://www.linkedin.com/checkpoint/lg/login-submit", allow_redirects=False, headers = headers, data=login_data, verify=True, proxies=None)
    if r.status_code == 403 or not r.cookies.get("li_at"):
        err("login request failed")
        exit(-1)
    return r.cookies.get("li_at")



# convert "lastname, JUNK, ..." to "lastname"
# or "lastname JUNK .."
# or "lastname Jr."
def sanitize_name(name):
    new_name = name
    if name.find(", ") > 0:
        new_name = name[:name.find(", ")]
    #hopefully all these Jr. put that at the end
    match = re.search(" [Jj][Rr]\.", new_name)
    if match:
        new_name = new_name[:match.start(1)]
    #if name.find(",") > 0:
    #    new_name = name[:name.find(",")]
    match = re.search("(?:[A-Za-z](?:[a-z]+|[ ]|[']))+( +[A-Z]{2,}.*)", new_name)
    if match:
        return new_name[:match.start(1)]
    else:
        return new_name

def get_search(companyID):

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
    '''
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
                    print(("[Notice] Found company ID: %s" % companyID))
                except:
                    continue
            companyID = firstID
            if companyID == 0:
                print("[WARNING] No valid company ID found in auto, please restart and find your own")
        else:
            # Don't auto, use the specified ID
            companyID = bSpecific
        
        print(("[*] Using company ID: %s" % companyID))
    '''
    # Fetch the initial page to get results/page counts
    if companyID == False:
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=0" % search
    else:
        info("Company ID: " + companyID)
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&keywords=%s&origin=OTHER&q=guided&start=0" % (companyID, search)
    
    print(url)
    
    headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
    cookies['JSESSIONID'] = 'ajax:0397788525211216808'
    #print(url)
    r = requests.get(url, cookies=cookies, headers=headers, verify=True, proxies=None)
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
        err("Try to use quotes in the search name")
        sys.exit(0)
    
    print(("[*] %i Results Found" % data_total))
    if data_total > 1000:
        pages = 25
        print("[*] LinkedIn only allows 1000 results. Refine keywords to capture all data")
    print(("[*] Fetching %i Pages" % pages))

    for p in range(int(pages)):
        # Request results for each page using the start offset
        if companyID == False:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=%i" % (search, p*40)
        else:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&keywords=%s&origin=OTHER&q=guided&start=%i" % (companyID, search, p*40)
        #print(url)
        r = requests.get(url, cookies=cookies, headers=headers, verify=True, proxies=None)
        content = r.text.encode('UTF-8')
        content = json.loads(content)
        print(("[*] Fetching page %i with %i results" % ((p),len(content['elements'][0]['elements']))))
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
                    print(("[*] No picture found for %s %s, %s" % (data_firstname, data_lastname, data_occupation)))
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
                
                

                csv.append( ('"%s","%s","%s","%s","%s", "%s"' % (data_firstname, original_lastname, name, email, data_occupation, data_location.replace(",",";")) ))
                foot = "</table></center>"
                f = open('{}.html'.format(outfile), 'wb')
                f.write(css.encode("utf-8"))
                f.write(header.encode("utf-8"))
                f.write(body.encode("utf-8"))
                f.write(foot.encode("utf-8"))
                f.close()
                f = open('{}.csv'.format(outfile), 'wb')
                f.write('\n'.join(csv).encode("utf-8"))
                f.close()
            else:
                print("[!] Headless profile found. Skipping")

def authenticate(username,password):
    try:
        a = login(username, password)
        print(a)
        session = a
        if len(session) == 0:
            sys.exit("[!] Unable to login to LinkedIn.com")
        print(("[*] Obtained new session: %s" % session))
        cookies = dict(li_at=session)
    except Exception as e:
        raise
    #    sys.exit("[!] Could not authenticate to linkedin. %s" % e)
    return cookies

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Discovery LinkedIn')
    parser.add_argument('-u', '--keywords', required=True, help='Keywords to search')
    parser.add_argument('-o', '--output', required=True, help='Output file (do not include extentions)')
    parser.add_argument('-i', '--companyid', help="companyID")
    parser.add_argument('-d', '--domain', required=True, help="email domain")
    parser.add_argument('-f', '--format', required=True, help="email format (full,firstlast,firstmlast,flast,firstl,first.last,fmlast,lastfirst)")
    args = parser.parse_args()
    config = configparser.RawConfigParser()
    config.read('LinkedInt.cfg')
    api_key = config.get('API_KEYS', 'hunter')
    username = config.get('CREDS', 'linkedin_username')
    password = config.get('CREDS', 'linkedin_password')

    search = args.keywords
    outfile = args.output

    if args.companyid:
        companyID = args.companyid
    else:
        companyID = False
            
    suffix = args.domain

    if not args.format or not args.format in ["full","firstlast","firstmlast","flast","firstl","first.last","fmlast","lastfirst"]:
        while True:
            prefix = input("[*] Select a prefix for e-mail generation (auto,full,firstlast,firstmlast,flast,firstl,first.last,fmlast,lastfirst): \n")
            prefix = prefix.lower()
            if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "firstl" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
                break
            elif prefix == "auto":
                #if auto prefix then we want to use hunter IO to find it.
                print("[*] Automatically using Hunter IO to determine best Prefix")
                url = "https://hunter.io/trial/v2/domain-search?offset=0&domain=%s&format=json" % suffix
                r = requests.get(url)
                content = json.loads(r.text)
                if "status" in content:
                    print("[!] Rate limited by Hunter IO trial")
                    url = "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s" % (suffix, api_key)
                    #print(url)
                    r = requests.get(url)
                    content = json.loads(r.text)
                    if "status" in content:
                        print("[!] Rate limited by Hunter IO Key")
                        continue
                #print(content)
                prefix = content['data']['pattern']
                print(("[!] %s" % prefix))
                if prefix:
                    prefix = prefix.replace("{","").replace("}", "")
                    if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "firstl" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
                        print(("[+] Found %s prefix" % prefix))
                        break
                    else:
                        print("[!] Automatic prefix search failed, please insert a manual choice")
                        continue
                else:
                    print("[!] Automatic prefix search failed, please insert a manual choice")
                    continue
            else:
                print("[!] Incorrect choice, please select a value from (auto,full,firstlast,firstmlast,flast,firstl,first.last,fmlast)")
    else:
        prefix = args.format

    
    # URL Encode for the querystring
    search = quote(search)
    cookies = authenticate(username,password)
    
    # Initialize Scraping
    get_search(companyID)

    print("[+] Complete")
