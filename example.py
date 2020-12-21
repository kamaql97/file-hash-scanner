"""
Palo Alto Networks Assignement - Kamal Qarain

Example usage code
"""

import sys
from solution.scanner import request_data

resource = sys.argv[1]

with open('example_output.md', 'w+') as output_file:
    output_file.write(request_data(resource))
