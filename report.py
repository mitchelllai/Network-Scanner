from texttable import Texttable
from sys import argv
import json

rows1 = [["domain", "ipv4_addresses", "ipv6_addresses", "http_server", "insecure_http", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]]
rtt = []
root_ca = {}
servers = {}
stats = {
    'SSLv2': 0,
    'SSLv3': 0,
    'TLSv1.0': 0,
    'TLSv1.1': 0,
    'TLSv1.2': 0,
    'TLSv1.3': 0,
    'plain http': 0,
    'https redirect': 0,
    'hsts': 0,
    'ipv6': 0
}
total_entries = 0
with open(argv[1], 'r') as input:
    data_dict = json.loads(input.read())
    total_entries = len(data_dict)
    for domain, data in data_dict.items():
        rows1.append([domain, data["ipv4_addresses"], data["ipv6_addresses"], data["http_server"], data["insecure_http"], data["redirect_to_https"], data["hsts"], data["tls_versions"], data["root_ca"], data["rdns_names"], data["rtt_range"], data["geo_locations"]])
        rtt.append((domain, data["rtt_range"]))
        if data["root_ca"] not in root_ca:
            root_ca[data["root_ca"]] = 1
        else:
            root_ca[data["root_ca"]] += 1
        if data["http_server"] not in servers:
            servers[data["http_server"]] = 1
        else:
            servers[data["http_server"]] += 1
        if data["insecure_http"]:
            stats['plain http'] += 1
        if data["redirect_to_https"]:
            stats["https redirect"] += 1
        if data["hsts"]:
            stats["hsts"] += 1
        if data["ipv6_addresses"]:
            stats["ipv6"] += 1
        if "TLSv1.0" in data["tls_versions"]:
            stats["TLSv1.0"] += 1
        if "TLSv1.1" in data["tls_versions"]:
            stats["TLSv1.1"] += 1      
        if "TLSv1.2" in data["tls_versions"]:
            stats["TLSv1.2"] += 1      
        if "TLSv1.3" in data["tls_versions"]:
            stats["TLSv1.3"] += 1             

table1 = Texttable()
table1.set_cols_align(["c"] * len(rows1[0]))
table1.set_cols_valign(["c"] * len(rows1[0]))
table1.set_cols_width([6] * len(rows1[0]))
table1.add_rows(rows1)
# print(table1.draw()+'\n')

rtt.sort(key=lambda range: range[1][0])
rows2 = [["domain", "rtt"]]+[[item[0], item[1]] for item in rtt]
table2 = Texttable()
table2.set_cols_align(["c"] * len(rows2[0]))
table2.set_cols_valign(["c"] * len(rows2[0]))
table2.set_cols_width([30] * len(rows2[0]))
table2.add_rows(rows2)
# print(table2.draw()+'\n')

root_ca = [[cert, count] for cert, count in root_ca.items()]
root_ca.sort(key=lambda cert_entry: cert_entry[1], reverse=True)
rows3 = [["root_ca", "count"]] + root_ca
table3 = Texttable()
table3.set_cols_align(["c"] * len(rows3[0]))
table3.set_cols_valign(["c"] * len(rows3[0]))
table3.set_cols_width([30] * len(rows3[0]))
table3.add_rows(rows3)
# print(table3.draw()+'\n')

servers = [[serv, count] for serv, count in servers.items()]
servers.sort(key=lambda serv_entry: serv_entry[1], reverse=True)
rows4 = [["server", "count"]] + servers
table4 = Texttable()
table4.set_cols_align(["c"] * len(rows4[0]))
table4.set_cols_valign(["c"] * len(rows4[0]))
table4.set_cols_width([30] * len(rows4[0]))
table4.add_rows(rows4)
# print(table4.draw()+'\n')

stats = [[stat, "{:.2f}".format((count/total_entries)*100)+'%'] for stat, count in stats.items()]
rows5 = [["stat", "percentage"]] + stats
table5 = Texttable()
table5.set_cols_align(["c"] * len(rows5[0]))
table5.set_cols_valign(["c"] * len(rows5[0]))
table5.set_cols_width([30] * len(rows5[0]))
table5.add_rows(rows5)
# print(table5.draw()+'\n')

with open(argv[2], 'w') as output:
    output.write(table1.draw() + '\n')
    output.write(table2.draw() + '\n')
    output.write(table3.draw() + '\n')
    output.write(table4.draw() + '\n')
    output.write(table5.draw() + '\n')