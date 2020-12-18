"""
Palo Alto Networks Assignement - Kamal Qarain
"""

import logging
import os

import requests
from requests.exceptions import HTTPError, RequestException

from solution.helpers import is_valid_hash, make_md_table


class FileScanner:
    '''
    Takes file's hash and makes a request to VirusTotal
    then returns report formatted as three markdown tables
    '''

    def __init__(self, resource=None):
        '''
        Configures error logging and checks if the VirusTotal
        API key exists on the system and if a hash is entred
        '''

        logging.basicConfig(
            filename='errors.log',
            level=logging.ERROR,
            format='%(asctime)s.%(msecs)03d %(levelname)s: %(funcName)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            )

        self.resource = resource
        if self.resource is None or not is_valid_hash(self.resource):
            raise TypeError('Enter a valid file hash (MD5, SHA-1, or SHA-256)')

        try:
            self.api_key = os.environ['VIRUSTOTAL_API_KEY']
        except KeyError:
            raise KeyError('Environmental variable not found')


    def request_data(self):
        '''
        Makes a get request to the VirusTotal server to scan the file
        then calls the `handle_response` method if there are no errors
        '''

        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.api_key, 'resource': self.resource}
            self.response = requests.get(url, params=params)
            self.response.raise_for_status()
        except ConnectionError as err:
            logging.error(err)
            raise   # Unable to connect
        except HTTPError as err:
            logging.error(err)
            raise   # Forbidden, NotFound, etc..
        except RequestException as err:
            logging.error(err)
            raise   # Other request handling error
        except Exception as err:
            logging.error(err)
            raise   # Some unknown error
        else:
            self.handle_response()


    def handle_response(self):
        '''
        Checks if JSON reponse is returned and if it contains
        the required keys to build the output tables
        '''

        try:
            data = self.response.json()
            hashes = [{'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}]
            resuls = [{'Total Scans': data['total'], 'Positive Scans': data['positives']}]
            scans = [{'Scan Origin': key, 'Scan Result': val['detected']} for key, val in data['scans'].items()]
        except ValueError as err:
            logging.error(err)
            raise ValueError('JSON response not returned')
        except KeyError as err:
            logging.error(err)
            raise KeyError('Dictionary key(s) not found')
        else:
            out_str = make_md_table('scanned file', hashes)
            out_str += make_md_table('results', resuls)
            out_str += make_md_table('scans', scans)
            with open('output.md', 'w+') as output_file:
                output_file.write(out_str)
