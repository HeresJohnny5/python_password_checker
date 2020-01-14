import requests
import hashlib


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError('Error feching: {}'.format(response.status.code))
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        print(h, count)


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)

    # print(first5_char, tail)
    # print(response.text)

    return get_password_leaks_count(response, tail)


pwned_api_check('Password123')
