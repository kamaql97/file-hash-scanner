"""
Palo Alto Networks Assignement - Kamal Qarain

File scanning code
"""

import logging
import os

import requests
from requests.exceptions import HTTPError, RequestException

from solution.helpers import is_valid_hash, make_md_table
from solution.exceptions import (InvalidFileHashError, APIKeyNotFoundError,
                                VirusTotalUnreachableError, UnexpectedResponseError)


class FileScanner:
    '''
    Takes file's hash and makes a request to VirusTotal
    then returns report formatted as three markdown tables

    Attributes:
        resource -- file's hash (MD5, SHA-1, or SHA-256)
        file_name -- name of file to write scan results
    '''

    def __init__(self, resource=None, file_name='output.md'):
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

        self.file_name = file_name

        self.resource = resource
        if self.resource is None or not is_valid_hash(self.resource):
            raise InvalidFileHashError()

        self.api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if self.api_key is None:
            raise APIKeyNotFoundError()


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
            raise VirusTotalUnreachableError()
        except HTTPError as err:
            logging.error(err)
            raise UnexpectedResponseError()
        except RequestException as err:
            logging.error(err)
            raise RequestException('Request could not be handled')
        except Exception as err:
            logging.error(err)
            raise Exception('An unknown error has occured')
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
        except Exception as err:
            logging.error(err)
            raise Exception('An unknown error has occured')
        else:
            out_str = (make_md_table('scanned file', hashes)
                        + make_md_table('results', resuls)
                        + make_md_table('scans', scans))
            with open(self.file_name, 'w+') as output_file:
                output_file.write(out_str)
            print(f'Process completed, check {self.file_name}')
