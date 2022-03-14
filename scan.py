from audioop import reverse
from sys import argv
from json import dump
from time import time
from subprocess import check_output, STDOUT
import re
import maxminddb
import geoip2.database
from geopy.geocoders import Nominatim

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

def scan_tls_versions(hostname):
    tls_versions = []
    try:
        nmap_output = check_output(['nmap', '--script', 'ssl-enum-ciphers', '-p' '443', hostname], timeout=2, stderr=STDOUT).decode('utf-8')
        if 'TLSv1.0' in nmap_output:
            tls_versions.append('TLSv1.0')
        if 'TLSv1.1' in nmap_output:
            tls_versions.append('TLSv1.1')
        if 'TLSv1.2' in nmap_output:
            tls_versions.append('TLSv1.2')
    except Exception as e:
        print('scan_tls_version: nmap failed - {}'.format(e))
    try:
        openssl_output = check_output(['openssl', 's_client', '-tls1_3', '-connect', hostname+':443'], input=b'',timeout=2, stderr=STDOUT).decode('utf-8')
        if 'TLSv1.3' in openssl_output:
            tls_versions.append('TLSv1.3')
    except Exception as e:
        print('scan_tls_version: openssl failed - {}'.format(e))  
    return tls_versions

def scan_root_ca(hostname):
    try:
        openssl_output = check_output(['openssl', 's_client', '-connect', hostname+':443'], input=b'', timeout=2, stderr=STDOUT).decode('utf-8')
        # print(openssl_output)
        cert_chain = list(filter(lambda header: 'Certificate chain' in header, openssl_output.split('---')))[0]
        root_cert = re.search('O = [\w\s.]+', cert_chain.splitlines()[-1]).group(0)
        return root_cert.split('O = ')[1]
    except Exception as e:
        print('scan_root_ca: openssl failed - {}'.format(e))
        return None

def scan_rdns_names(ipv4_addresses):
    rdns_names = set()
    for ip_addr in ipv4_addresses:
        try:
            host_output = check_output(['host', ip_addr], timeout=2, stderr=STDOUT).decode('utf-8').splitlines()
            for line in host_output:
                rdns_names.add(line.split()[-1][:-1])

        except Exception as e:
            print('scan_rdns_names: host command failed for {}- {}'.format(ip_addr,e))
    return list(rdns_names)
def scan_rtt_range(ipv4_addresses):
    min_rtt = float('inf')
    max_rtt = float('-inf')
    ports = ['443', '80']
    for ip_addr in ipv4_addresses:
        for port in ports:
            try:
                time_output = check_output("sh -c \"time echo -e '\\x1dclose\\x0d' | telnet {} {}\"".format(ip_addr, port), timeout=2, shell=True, stderr=STDOUT).decode('utf-8').splitlines()
                # print(time_output)
                rtt = int(float(list(filter(lambda line: 'real' in line, time_output))[0].split('m')[1].split('s')[0]) * 1000)
                if rtt > max_rtt:
                    max_rtt = rtt
                if rtt < min_rtt:
                    min_rtt = rtt
            except Exception as e:
                print('scan_rtt_range: rtt failed - {}'.format(e))
    if min_rtt == float('inf') and max_rtt == float('-inf'):
        return None
    return [min_rtt, max_rtt]
            

def scan_geo_locations(ipv4_addresses):
    geo_locations = set()
    for ip_addr in ipv4_addresses:
        try:
            with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
                geolocation = reader.get(ip_addr)
                geolocator = Nominatim(user_agent='340-network-scanner')
                location = geolocator.reverse(str(geolocation['location']['latitude']) + ", " + str(geolocation['location']['longitude']))
                address = location.raw['address']
                geo_locations.add(address['county'] + ', ' + address['state'] + ', ' + address['country'])
        except Exception as e:
            print('scan_geo_locations failed: {}'.format(e))

    return list(geo_locations)

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
            json_object[hostname]['tls_versions'] = scan_tls_versions(hostname)
            json_object[hostname]['root_ca'] = scan_root_ca(hostname)

            json_object[hostname]['rdns_names'] = scan_rdns_names(ipv4_addresses)
            json_object[hostname]['rtt_range'] = scan_rtt_range(ipv4_addresses)
            json_object[hostname]['geo_locations'] = scan_geo_locations(ipv4_addresses)

    with open(argv[2], 'w') as output:
        dump(json_object, output, sort_keys=True, indent=4)

dev = False
if dev:
    # # print(curl_get_request('twitter.com/', https=True).decode('utf-8').splitlines())
    # print(check_output(['openssl', 's_client', '-tls1_3', '-connect', 'tls13.cloudflare.com:443'], stderr=STDOUT).decode('utf-8'))
    with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
        geolocation = reader.get('129.105.1.129')
        # print(geolocation)
        geolocator = Nominatim(user_agent='340-network-scanner')
        location = geolocator.reverse(str(geolocation['location']['latitude']) + ", " + str(geolocation['location']['longitude']))
        print(location.raw)
    # with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
    #     geolocation = reader.city('129.105.136.48')
    #     # print(geolocation.location.latitude)
    #     geolocator = Nominatim(user_agent='340-network-scanner')
    #     location = geolocator.reverse(str(geolocation.location.latitude) + ", " + str(geolocation.location.longitude))
    #     print(location)
        # geolocator = Nominatim(user_agent='340-network-scanner')
        # print(geolocation)
        # location = geolocator.reverse(str(geolocation['location']['latitude']) + ", " + str(geolocation['location']['longitude']))
        # print(location)
        # print(geolocation)
        # print(type(geolocation['location']['latitude']))
        # print(reverse_geocode.search((geolocation['location']['latitude'], geolocation['location']['longitude'])))
else:
    scan()

