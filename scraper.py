import pandas as pd
from urllib.request import urlopen
from bs4 import BeautifulSoup
from datetime import datetime
import json
import argparse as ap

# input the target url
parser = ap.ArgumentParser()
parser.add_argument("input_url", help="specifies the url to scrape", type=str)
arguments = parser.parse_args()
ORIGIN_URL = arguments.input_url

cves = [] 

first_page = urlopen(ORIGIN_URL)
bsObj = BeautifulSoup(first_page.read(), 'html.parser')
vulnerability_details = bsObj.findAll('div', {'class': 'table parbase section'})[3]

timestamp = datetime.now().strftime('%Y-%m-%dT%H:%mZ')
name = bsObj.find('div', {'class': 'page-description'}).text.replace('\t','').replace('\n','')
url = ORIGIN_URL
published_date = bsObj.find('div',{'class':'table parbase section'}).findAll('tr')[1].findAll('td')[1].text.replace('\xa0','')
published_date = datetime.strptime(published_date, '%B %d, %Y').date()
published_date = published_date.strftime('%Y-%m-%dT%H:%mZ')

if(vulnerability_details.text.find('Affected Versions') == -1):  # the first case
    cpe_list = []
    affected_versions = bsObj.findAll('div', {'class': 'table parbase section'})[1].findAll('tr')
    affected_versions_headers = affected_versions[0].findAll('th')
    version_col = 0
    for item in affected_versions_headers:
        if ("Version" in item.text.replace('\n', '')):
            break
        else:
            version_col += 1

    for ind in range(1, len(affected_versions)):
        version = affected_versions[ind].findAll('td')[version_col].text.split(' ')[0]
        product = affected_versions[ind].findAll('td')[0].text.replace('\u00a0','').replace('\n','')
        dict = {'vendor':'magento', 'product':product, 'category':'a', 'versionEndIncluding':version}
        cpe_list.append(dict)
        
    cpes = {'cpe_list':cpe_list}
    vulnerability_details_headers = vulnerability_details.findAll('tr')[0].findAll('td')
    if (len(vulnerability_details_headers) == 0):
        vulnerability_details_headers = vulnerability_details.findAll('tr')[0].findAll('th')
    cve_number = 0
    for item in vulnerability_details_headers:
        if ("CVE Number" in item.text.replace('\n', '')):
            break
        else:
            cve_number += 1
 
    for ind in range(1, len(vulnerability_details.findAll('tr'))):

        ID = vulnerability_details.findAll('tr')[ind]
        ID = ID.findAll('td')[cve_number].text.replace('\xa0', '').replace('\n','')
        description = vulnerability_details.findAll('tr')[ind].findAll('td')[0].text.replace('\xa0', '').replace('\n','').replace('\u202f','')
        dict = {'timestamp':timestamp, 'published_date':published_date, 'id':ID, 'url':url, 'name':name, 'description':description, 'cpes':cpes}
        cves.append(dict)
   
else:       # the second case
    affected_versions = bsObj.findAll('div', {'class': 'table parbase section'})[1].findAll('tr')
    product = affected_versions[1].findAll('td')[0].text.replace('\u00a0','').replace('\n','')
    for ind in range(1, len(vulnerability_details)):
        cpe_list = []
        vulnerability_details_headers = vulnerability_details.findAll('tr')[0].findAll('td')
        if (len(vulnerability_details_headers) == 0):
            vulnerability_details_headers = vulnerability_details.findAll('tr')[0].findAll('th')
        
        cve_number = 0
        for item in vulnerability_details_headers:
            
            if ("CVE Number" in item.text.replace('\n', '')):
                break
            else:
                cve_number += 1
      
        ID = vulnerability_details.findAll('tr')[ind].findAll('td')[cve_number].text.replace('\xa0', '').replace('\n','')
        description = vulnerability_details.findAll('tr')[ind].findAll('td')[0].text.replace('\xa0', '').replace('\n','').replace('\u202f','')
        versions = vulnerability_details.findAll('tr')[ind].findAll('td')[4]
        if len(versions.findAll('p')) > 0:
            versionStartIncluding = versions.findAll('p')[0].text.replace('\n','').replace('\u00a0','').split(' ')[-1]
            versionEndIncluding = versions.findAll('p')[-1].text.replace('\n','').replace('\u00a0','').split(' ')[-1]
        else:
            versionStartIncluding = versions.text.replace('\n','').replace('\u00a0','')
            versionEndIncluding = versions.text.replace('\n','').replace('\u00a0','')

        dict = {'vendor':'adobe', 'product':product, 'category':'a', 'versionStartIncluding':versionStartIncluding, 'versionEndIncluding': versionEndIncluding}
        cpe_list.append(dict)
        cpes = {'cpe_list':cpe_list}
        dict = {'timestamp':timestamp, 'published_date':published_date, 'id':ID, 'url':url, 'name':name, 'description':description, 'cpes':cpes}
        cves.append(dict)

dict = {'source': 'adobe', 'type': 'vendor', 'cves': cves}
result = json.dumps(dict)

# write the json to the file
with open("sample.json", "w") as outfile: 
    outfile.write(result) 
