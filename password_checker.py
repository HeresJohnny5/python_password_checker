import requests
import hashlib


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError('Error feching: {}'.format(res.status.code))
    return res


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    return sha1_password


request_api_data('B2E98')
