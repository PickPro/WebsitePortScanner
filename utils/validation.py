# utils/validation.py

import re

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def is_valid_hostname(hostname):
    pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,6})+$"
    )
    return pattern.match(hostname) is not None

def strip_protocol(url):
    return re.sub(r'^https?://', '', url)

def remove_trailing_slash(url):
    return url.rstrip('/')