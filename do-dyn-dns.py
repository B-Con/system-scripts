#!/usr/bin/python3
"""
Use a DigitalOcean (sub)domain for a dynamic DNS service.

Updates a Digital Ocean domain A record with the current external IP address. 
Optionally verifies the HTTPS connection. Optionally creates the record if it
doesn't exist.

Brad Conte (brad@bradconte.com)
"""

from http.client import HTTPSConnection
from http.client import HTTPConnection
import ssl
import json
import sys


# =========================================================================
# Globals
# =========================================================================


# The domain registered with Digital Ocean. Eg: name.com
DOMAIN_NAME = ""
# The record name, Eg: "dynamicip" for "dynamicip.name.com"
RECORD_NAME = ""
# Get these from: https://www.digitalocean.com/api_access
CLIENT_ID = ""
API_KEY = ""
# Verify the HTTP cert for the API?
CHECK_CERT = True
# Path to SSL CA certificates. Eg: /etc/ssl/certs/
CERT_PATH = ""


# =========================================================================
# Classes and Methods
# =========================================================================


class NoRecordException(Exception):
    pass


class APIException(Exception):
    """Thrown when an Digital Ocean API request returns an error.
    
    Attributes:
        api_msg - the error message returned by the API
        api_call - the API call that generated the error
    """
    def __init__(self, api_msg, api_call):
        self.api_msg = api_msg
        self.api_call = api_call

    def __str__ (self):
        return 'API failed. Error msg = "{}", attempted API = "{}".'.format(
                self.api_msg, self.api_call)


class DigitalOceanAPI(object):
    """A general Digital Ocean API wrapper. A single SSL connection is made
    when the object is instantiated and kept until it's deleted. API requests
    are returned in parsed JSON. API failures throw an exception. SSL
    parameters are pass-through to the SSL module. Requires the D.O. Client ID 
    and API Key for the account.
    
    Keyword Arguments:
        check_cert - whether the HTTPS connection's cert should be verified
        pemfile - path to PEM file, such as "/etc/ssl/certs/ca-certificates.pem"
        capath - path to list of CA certs, such as "/etc/ssl/certs/"

    Requires:
        ssl
        json
        http.client
    """

    api_host = "api.digitalocean.com"
    
    # "check_cert" is True by default because we have API keys we're sending.
    # By default, this means at least one of the keyword arguments must always
    # be supplied since checking the cert requires a cert path, which has no
    # working default.
    def __init__(self, client_id, api_key, check_cert = True, pemfile = None, 
            capath = None):
        self.connection = None
        self.auth_data = ""

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        if check_cert:
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_ctx.load_verify_locations(pemfile, capath)
        else:
            ssl_cts.verify_mode = ssl.CERT_NONE
        
        self.connection = HTTPSConnection(
                DigitalOceanAPI.api_host, context=ssl_ctx)
        self.auth_data = "&client_id={}&api_key={}".format(client_id, api_key)

    def __enter__(self):
        return self

    def request(self, url):
        """Perform an API request and returns the parsed JSON data. Throws
        an exception with API description if the response is an error. See
        api.digitalocean.com for API usage.
        
        Arguments:
        url - API call, minus auth, ex: "/domains/new?data=127.0.0.1&name=home"
        """
        # If the URL doesn't contain arguments, add the "?" so we an append
        # the self-auth arguments.
        final_url = url
        if not "?" in final_url:
            final_url += "?"
        final_url += self.auth_data
        self.connection.request("GET", final_url)
        response = self.connection.getresponse()
        response_data = json.loads(response.read().decode("utf-8"))
        response.close()

        if response_data["status"] != "OK":
            raise APIException(response_data["message"], url)
        return response_data
    
    def close(self):
        if not self.connection is None:
            self.connection.close()
            self.connection = None
        self.auth_data = ""

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        
    def __del__(self):
        self.close()


def get_external_ip():
    connection = HTTPConnection("ifconfig.me")
    connection.request("GET", "/ip")
    response = connection.getresponse()
    ip = response.read().decode("utf-8").strip()
    response.close()
    connection.close()
    return ip


def get_domain_info(api):
    url = "/domains/"
    response = api.request(url)
    for domain in response["domains"]:
        if domain["name"] == DOMAIN_NAME:
            return domain
    raise Exception("Didn't find domain '{}'".format(DOMAIN_NAME))


def get_record_info(domain_id, api):
    url = "/domains/{}/records".format(domain_id)
    response = api.request(url)
    for record in response["records"]:
        if record["name"] == RECORD_NAME:
            if record["record_type"] == "A":
                return record
            else:
                raise Exception("Record type is '{}' but should be 'A'".format(
                        record["record_type"]))
    raise NoRecordException


def update_record_ip(domain_id, record_id, ip, api):
    url = "/domains/{}/records/{}/edit".format(domain_id, record_id)
    data = "?data={}".format(ip)
    api.request(url + data)


def create_record(domain_id, ip, api):
    url = "/domains/{}/records/new".format(domain_id)
    data = "?record_type=A&name={}&data={}".format(RECORD_NAME, ip)
    api.request(url + data)


def main(should_create_record):
    ip = get_external_ip()
    
    with DigitalOceanAPI(CLIENT_ID, API_KEY, CHECK_CERT, capath=CERT_PATH) \
            as api:
        domain = get_domain_info(api)
        try:
            record = get_record_info(domain["id"], api)
            old_ip = record["data"]
            if ip != old_ip:
                update_record_ip(domain["id"], record["id"], ip, api)
                print("Updated IP: old = {}, new = {}".format(old_ip, ip))
            else:
                print("No change: IP = {}".format(old_ip))
        except NoRecordException:
            if should_create_record:
                create_record(domain["id"], ip, api)
                print("Created record '{}': IP = {}".format(RECORD_NAME, ip))
            else:
                raise Exception("Didn't find record '{}'".format(RECORD_NAME))

    # All errors throw an exception.
    return True


def help():
    print(
    """Usage: digitalocean-dyn-dns [-h] [-c]

    -h : Show this help message
    -c : Create the DNS A record if it doesn't already exist
    """)


if __name__ == "__main__":
    if "-h" in sys.argv:
        help()
        exit(0)

    should_create_record = True if "-c" in sys.argv else False
    
    success = False
    try:
        success = main(should_create_record)
    except Exception as ex:
        sys.stderr.write("Error: {}\n".format(ex))
        success = False
    except:
        sys.stderr.write("Unhandled generic error\n")
    
    sys.exit(not success)

