from sys import argv
from json import dump

json_object = {}
with open(argv[1], 'r') as input:
    websites = input.read().splitlines()
    for website in websites:
        json_object[website] = {}

# with open(argv[2], 'w') as output:
#     dump(json_object, f, sort_keys=True, indent=4)

print(json_object)