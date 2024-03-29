"""
Palo Alto Networks Assignement - Kamal Qarain

File scanning code
"""

import logging
import os

from collections import OrderedDict
import requests
from requests.exceptions import HTTPError, RequestException

from solution.helpers import is_valid_hash, make_md_table, get_days_diff


logging.basicConfig(filename='errors.log', level=logging.ERROR,
                    format='%(asctime)s.%(msecs)03d %(levelname)s: %(funcName)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


def request_data(resource=None, user_key=None):
    '''
    Method that checks for exisitance of API key and a valid file hash,
    then makes a get request to the VirusTotal Service

    Inputs:
        resource --- String representing a file's hash
        user_key --- Optional string; VirusTotal API key (if not in environmental variables)

    Output:
        String containg the scan results (if the file could be scanned)
    '''

    if resource is None or not is_valid_hash(resource):
        raise Exception('Enter a valid file hash (MD5, SHA-1, or SHA-256)')

    api_key = os.environ.get('VIRUSTOTAL_API_KEY', user_key)
    if api_key is None:
        raise Exception('Could not find VirusTotal API Key')

    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params)
        response.raise_for_status()
    except ConnectionError as err:
        logging.error(err)
        raise
    except HTTPError as err:
        logging.error(err)
        raise 
    except RequestException as err:
        logging.error(err)
        raise
    except Exception as err:
        logging.error(err)
        raise Exception('An unknown error has occured')
    else:
        return handle_data(response.json())


def handle_data(data):
    '''
    Method that attemps to parse the JSON response returned by the service

    Inputs:
        data --- reponse JSON to be decoded 

    Output:
        String containg the scan results (if the file could be scanned)
    '''
    
    out_str = ''

    try:
        msg = data['verbose_msg']

        if data['response_code'] == 1:      # item present and could be retrieved

            sorted_scans = OrderedDict(sorted(data['scans'].items()))
            hashes = [{'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}]
            resuls = [{'Total Scans': data['total'], 'Positive Scans': data['positives']}]
            scans = [{'Scan Origin': key, 'Scan Result': val['result'], 'Days since scan': get_days_diff(str(val['update']))}
                    for key, val in sorted_scans.items()]

            out_str = (make_md_table('scanned file', hashes)
                        + make_md_table('results', resuls)
                        + make_md_table('scans', scans))

    except ValueError as err:
        logging.error(err)
        raise
    except KeyError as err:
        logging.error(err)
        raise
    except Exception as err:
        logging.error(err)
        raise Exception('An unknown error has occured')
    else:
        print (msg)
        return out_str
