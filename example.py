"""
Palo Alto Networks Assignement - Kamal Qarain

Example usage code
"""

from solution.scanner import request_data


with open('output.md', 'w+') as output_file:
    output_file.write(request_data('84c82835a5d21bbcf75a61706d8ab549'))
