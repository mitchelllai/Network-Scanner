from sys import argv, stdout
from json import dump
from time import time
from subprocess import check_output, STDOUT

def dns_resolvers():
    with open('public_dns_resolvers.txt', 'r') as dns_res_file:
        dns_resolvers = dns_res_file.read().splitlines()
        dns_resolvers.append('')
        return dns_resolvers

def scan_ip_addresses(hostname, dns_resolvers):
    ipv4_addresses = set()
    ipv6_addresses = set()
    for dns_resolver in dns_resolvers:
        command = ['nslookup', hostname]
        if dns_resolver != '':
            command.append(dns_resolver)
        try:
            ns_lookup_output = check_output(command, timeout=2, stderr=STDOUT).decode('utf-8')
        except Exception as e:
            print(e)
            continue
        dns_records = ns_lookup_output.splitlines()[4:]
        for record in dns_records:
            if 'Address: ' in record:
                ip_addr = record.split('Address: ')[1]
                if ':' in ip_addr:
                    ipv6_addresses.add(ip_addr)
                else:
                    ipv4_addresses.add(ip_addr)
    return list(ipv4_addresses), list(ipv6_addresses)

def curl_get_request(hostname, https=False):
    try:
        if https:
            command = ['curl', '-Is', 'https://'+hostname]
        else:
            command = ['curl', '-Is', 'http://'+hostname]
        curl_response = check_output(command, timeout=2, stderr=STDOUT)
        return curl_response
    except Exception as e:
        print('curl_get_request: {}'.format(e))
        return None

def scan_http_server(curl_response, hostname):
    if not curl_response:
        return None
    try:
        curl_resp_formatted = curl_response.decode('utf-8').splitlines()
        server = list(filter(lambda header: 'Server: ' in header, curl_resp_formatted))[0].split('Server: ')[1]
        return server
    except IndexError:
        print('scan_http_server: No Server Header Found for {}'.format(hostname))
        return None
    except Exception as e:
        print('scan_http_server: {}'.format(e))
        return None

def scan_insecure_http(curl_response):
    return curl_response is not None
    
def scan_redirect_to_https(curl_response):
    if not curl_response:
        return False
    try:
        curl_resp_formatted = curl_response.decode('utf-8').splitlines()
        relevant_headers = list(filter(lambda header: 'HTTP/' in header or 'Location: ' in header or 'location: ' in header, curl_resp_formatted))
        status_code = relevant_headers[0].split()[1]
        max_redirects = 10
        while max_redirects > 0 and '30' in status_code:
            location = relevant_headers[1].split()[1]
            if 'https://' in location:
                return True
            try:
                curl_resp_formatted = curl_get_request(location.split('http://')[1]).decode('utf-8').splitlines()
            except Exception as e:
                print('scan_redirect_to_https: curl failed with error - {}'.format(e))
                return False
            relevant_headers = list(filter(lambda header: 'HTTP/' in header or 'Location: ' in header or 'location: ' in header, curl_resp_formatted))
            status_code = relevant_headers[0].split()[1]
            max_redirects -= 1
        return False
    except Exception as e:
        print('scan_redirect_to_https: {}'.format(e))
        return False

def scan_hsts(hostname):
    try:
        curl_resp_formatted = curl_get_request(hostname).decode('utf-8').splitlines()
    except Exception as e:
        print('scan_hsts: curl failed with error - {}'.format(e))
    relevant_headers = list(filter(lambda header: 'HTTP/' in header or 'Location: ' in header or 'location: ' in header, curl_resp_formatted))
    status_code = relevant_headers[0].split()[1]
    max_redirects = 10
    while max_redirects > 0 and '30' in status_code:
        location = relevant_headers[1].split()[1]
        try:
            if 'https://' in location:
                curl_resp_formatted = curl_get_request(location.split('https://')[1], https=True).decode('utf-8').splitlines()
            else:
                curl_resp_formatted = curl_get_request(location.split('http://')[1]).decode('utf-8').splitlines()
        except Exception as e:
            print('scan_hsts: curl failed with error - {}'.format(e))
        relevant_headers = list(filter(lambda header: 'HTTP/' in header or 'Location: ' in header or 'location: ' in header, curl_resp_formatted))
        status_code = relevant_headers[0].split()[1]
        max_redirects -= 1
    if max_redirects == 0 and '30' in status_code:
        print('scan_hsts: max redirects reached')
        return False
    hsts_header = list(filter(lambda header: 'strict-transport-security' in header or 'Strict-Transport-Security' in header, curl_resp_formatted))
    return len(hsts_header) == 1
        
def scan():
    DNS_RESOLVERS = dns_resolvers()
    json_object = {}
    with open(argv[1], 'r') as input:
        hostnames = input.read().splitlines()
        for hostname in hostnames:
            json_object[hostname] = {'scan_time': time()}

            ipv4_addresses, ipv6_addresses = scan_ip_addresses(hostname, DNS_RESOLVERS)
            json_object[hostname]['ipv4_addresses'] = ipv4_addresses
            json_object[hostname]['ipv6_addresses'] = ipv6_addresses
            
            curl_response = curl_get_request(hostname)
            json_object[hostname]['http_server'] = scan_http_server(curl_response, hostname)
            json_object[hostname]['insecure_http'] = scan_insecure_http(curl_response)
            json_object[hostname]['redirect_to_https'] = scan_redirect_to_https(curl_response)

            json_object[hostname]['hsts'] = scan_hsts(hostname)

    with open(argv[2], 'w') as output:
        dump(json_object, output, sort_keys=True, indent=4)

dev = False
if dev:
    print(curl_get_request('twitter.com/', https=True).decode('utf-8').splitlines())
else:
    scan()

