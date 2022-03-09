from sys import argv
from json import dump
from time import time

json_object = {}
with open(argv[1], 'r') as input:
    websites = input.read().splitlines()
    for website in websites:
        json_object[website] = {'scan_time': time()}

with open(argv[2], 'w') as output:
    dump(json_object, output, sort_keys=True, indent=4)

