"""
Palo Alto Networks Assignement - Kamal Qarain

File scanning code
"""

import logging
import sys
import os

import requests
from requests.exceptions import HTTPError, RequestException

from solution.helpers import is_valid_hash, make_md_table
from solution.exceptions import (InvalidFileHashError, APIKeyNotFoundError,
                                VirusTotalUnreachableError, UnexpectedResponseError)


def request_data(resource=None):
    '''
    Method that configures error logging, checks for exisitance of API key
    and a valid file hash, then makes a get request and returns the JSON reponse
    as a string in the markdown format
    '''

    logging.basicConfig(filename='errors.log', level=logging.ERROR,
                        format='%(asctime)s.%(msecs)03d %(levelname)s: %(funcName)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    
    out_str = ''

    if resource is None or not is_valid_hash(resource):
        raise InvalidFileHashError()

    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if api_key is None:
        raise APIKeyNotFoundError()

    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params)
        response.raise_for_status()
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
        try:
            data = response.json()
              
            if data['response_code'] == 1:  # item present and could be retrieved
                print(data['verbose_msg'])

                hashes = [{'MD5': data['md5'], 'SHA-1': data['sha1'], 'SHA-256': data['sha256']}]
                resuls = [{'Total Scans': data['total'], 'Positive Scans': data['positives']}]
                scans = [{'Scan Origin': key, 'Scan Result': val['detected']}
                        for key, val in data['scans'].items()]

                out_str = (make_md_table('scanned file', hashes)
                            + make_md_table('results', resuls)
                            + make_md_table('scans', scans))
            else:               # not in database [0] or still queued for analysis [-2]
                sys.exit(data['verbose_msg'])
        except ValueError as err:
            logging.error(err)
            raise 
        except KeyError as err:
            logging.error(err)
            raise 
        except Exception as err:
            logging.error(err)
            raise Exception('An unknown error has occured')
        return out_str
