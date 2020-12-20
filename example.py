"""
Palo Alto Networks Assignement - Kamal Qarain

Example usage code
"""

from solution.scanner import request_data

with open('output.md', 'w+') as output_file:
    output_file.write(request_data('6E0B782A9B06834290B24C91C80B12D7AD3C3133'))
