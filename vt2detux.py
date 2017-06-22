__author__ = "s4g4"
__date__ = "$17 Jan, 2017 4:00:00 PM$"

"""
	This file will collect the samples from Vt and submit to detux
	usage : python v2detux.py

	----
	please Update VT_API_KEY, DETUX_API_KEY and query accordingly

"""

import requests
from datetime import date, timedelta
import json
import urllib
import os.path
from os import walk
from base64 import b64encode

VT_API_KEY = 'API_KEY'
DETUX_API_KEY = "API_KEY"
SAMPLE_FOLDER = "./samples/"


def searchInVT(query,page='undefined'):
	headers = {
	    "Accept-Encoding": "gzip, deflate",
	    "User-Agent" : "gzip,  My Python requests library"
	}


	params = {'apikey': VT_API_KEY, 'query': query,'page':page}

	response = requests.post('https://www.virustotal.com/intelligence/search/programmatic/', data=params, headers=headers)

	return response.json()


def downloadFromVt(file_hash):
	"""Downloads the file with the given hash from Intelligence.

    Args:
      file_hash: either the md5, sha1 or sha256 hash of a file in VirusTotal.
      destination_file: full path where the given file should be stored.

    Returns:
      True if the download was successful, False if not.
    """
   	destination_file = SAMPLE_FOLDER+"/"+file_hash
   	if not os.path.isfile(destination_file):
	   	download_url = 'https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s' % (file_hash, VT_API_KEY)
	   	attempts = 0
	   	while attempts < 3:
	   	   	try:
				urllib.urlretrieve(download_url, destination_file)
				return True
			except Exception:
				attempts += 1
		return False
	else:
		return True




def isFileInDetux(file_hash):
	params = {'api_key': DETUX_API_KEY,'search':file_hash}
	response = requests.post('https://detux.org/api/search.php', data=params)
	resp = response.json()
	if resp['status'] == "0":
		return False
	else :
		return True


def uploadFileInDetux(file_hash):
	submit_url = 'https://detux.org/api/submit.php'
	result =  {}
	filepath = SAMPLE_FOLDER+"/"+file_hash
	if os.path.isfile(filepath):
	    with open(filepath) as f:
	        data = f.read()
	    b64data = b64encode(data)
	    postdata = {'api_key': DETUX_API_KEY,'file': b64data,'private': 1}
	    res = requests.post(submit_url,data=postdata,verify=False)
	    if res.status_code == 200:
	        rjson = res.json()
	        if rjson['status'] == '1':
	            result = rjson
	            print "file submitted successfully"
	        else:
	            result = rjson
	            result['error'] = "Error Submitting File"
	else:
	    result = {'error': 'File not found on harddisk'}

	return result





if __name__ == "__main__":
	yesterday_date = date.today() - timedelta(1)
	yesterday = yesterday_date.strftime('%Y-%m-%dT00:00:00')	

	query = 'avg:Linux/Fgt OR sophos: Linux/Tsunami-A AND fs:'+yesterday+"+"
	vt_res = searchInVT(query)

   	hashes = vt_res['hashes']
   	next_page = vt_res['next_page']
   	 
   	while next_page != None:
   		vt_res = searchInVT(query,next_page)
   		next_page = vt_res['next_page']
   		hashes.extend(vt_res['hashes'])
	
	print "total samples : "+str(len(hashes))

	i = 0
   	for filehash in hashes:
   		i=i+1
   		print "sample no : "+ str(i)
 		if isFileInDetux(filehash):
 			print "Already in detux, "+ str(filehash)
   		else:
   			print "downloading file "+ str(filehash)
   			if downloadFromVt(filehash):
   				print "uploading file to detux "+ str(filehash)
   				uploadFileInDetux(filehash)
   				os.remove(SAMPLE_FOLDER+"/"+filehash)

   	print "job finished successfully !"
