"""
Palo Alto Networks Assignement - Kamal Qarain

Helper methods for input validation and output formatting
"""

import re
import datetime


def is_valid_hash(file_hash):
    """
    Method to check for valid file hash
    (Simple check, API returns response_code 0 if not recognised)

    Inputs:
        file_hash --- String representing a file's hash
    
    Output:
        Boolean flag (True or False)
    """

    return bool(re.match("^[a-fA-F0-9]{64}$", file_hash)        # SHA-256
                or re.match("^[a-fA-F0-9]{40}$", file_hash)     # SHA-1
                or re.match("^[a-fA-F0-9]{32}$", file_hash))    # MD5


def make_md_table(title, dicts):
    '''
    Method to build a markdown table

    Inputs:
        title --- String represnting table title
        dicts --- List of dictionaries represnting table contents
    
    Output:
        String in markdown formatting
    '''

    ans_str = "\n"
    table_cols = list(dicts[0].keys() if dicts else [])
    table_rows = [["_"+ col_name +"_" for col_name in table_cols]]
    for one_dict in dicts:
        table_rows.append([str(one_dict[col] if one_dict[col] is not None else "") for col in table_cols])
    max_col_widths = [max(map(len,col)) for col in zip(*table_rows)]
    table_rows.insert(1, ["-" * width for width in max_col_widths])
    joined_str = "|".join(["{{:<{}}}".format(i) for i in max_col_widths])
    ans_str += f"### {title}\n".title()
    for row in table_rows:
        ans_str += joined_str.format(*row) + "\n"
    return ans_str


def get_days_diff(my_date):
    scan_date = datetime.date.fromisoformat(my_date[0:4] + '-' + my_date[4:6] + '-' + my_date[6:])
    today_date = datetime.date.today()
    return today_date - scan_date
