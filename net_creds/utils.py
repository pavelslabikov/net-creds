def double_line_checker(full_load, count_str):
    '''
    Check if count_str shows up twice
    '''
    num = full_load.lower().count(count_str)
    if num > 1:
        lines = full_load.count('\r\n')
        if lines > 1:
            full_load = full_load.split('\r\n')[-2] # -1 is ''
    return full_load
