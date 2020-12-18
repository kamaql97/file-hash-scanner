import re


def is_valid_hash(file_hash):
    """
    Checks if the inputted string is a valid file hash
    """
    
    return bool(re.match("^[a-fA-F0-9]{64}$", file_hash)        # SHA-256
                or re.match("^[a-fA-F0-9]{40}$", file_hash)     # SHA-1
                or re.match("^[a-fA-F0-9]{32}$", file_hash))    # MD5


def make_md_table(title, input_dict):
    '''
    Takes list of dictionaries and builds a markdown table
    '''

    ans_str = "\n"
    table_cols = list(input_dict[0].keys() if input_dict else [])
    table_rows = [["_"+ col_name +"_" for col_name in table_cols]]
    for item in input_dict:
        table_rows.append([str(item[col] if item[col] is not None else "") for col in table_cols])
    max_col_widths = [max(map(len,col)) for col in zip(*table_rows)]
    table_rows.insert(1, ["-" * width for width in max_col_widths])
    joined_str = "|".join(["{{:<{}}}".format(i) for i in max_col_widths])
    ans_str += f"### {title}\n".title()
    for row in table_rows:
        ans_str += joined_str.format(*row)
        ans_str += "\n"
    return ans_str
