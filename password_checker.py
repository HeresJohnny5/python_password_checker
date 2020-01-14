import sys
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
        if h == hash_to_check.upper():
            return count
    return 0


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)

    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)

        if count:
            print('Password {} was found {} times. You probably should consider creating a new password'.format(
                password, count))
        else:
            print('Password {} was not found. Please continue.'.format(password))

        return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
