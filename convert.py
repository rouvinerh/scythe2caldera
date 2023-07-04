#!/usr/bin/python3

import uuid
import json
import sys
import os
from mitre_tactics import mitre_tactics
from ruamel.yaml import YAML

uuid_list = []
# tactics = ['collection', 'command-and-control', 'credential-access', 'defense-evasion', 'discovery', 'execution', 'exfiltration', 'impact', 'initial-access', 'lateral-movement', 'multiple', 'persistence', 'privilege-escalation', 'reconnaissance', 'technical-information-gathering']

def generate_adversary_id():
    return str(uuid.uuid4())

def lookup_tactic(tech):
    for tactic, techniques in mitre_tactics.items():
        if tech in techniques:
            return tactic
    return None

def scrape_json(json_file_path):
    with open(json_file_path, 'r') as json_file:
        json_data = json.load(json_file)
    script = json_data.get("threat", {}).get("script", {})
    adversary_name = json_data["threat"]["name"]
    description = json_data["threat"]["description"]
    
    if os.path.exists('cmd.txt'):
        os.remove('cmd.txt')

    with open('cmd.txt', 'a') as output_file:
        for key, value in script.items():
            if isinstance(value, dict) and value.get("module") == "run":
                cmd = value.get("request")
                rtags = value.get("rtags", [])
                for rtag in rtags:
                    if rtag.startswith("att&ck-technique:"):
                        technique = rtag.split(":")[1]
                        output = f"{technique} --> {cmd}\n"
                        output_file.write(output)
    return adversary_name, description

def create_directories():
    directories = ['adversaries', 'abilities']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

def generate_abilities():
    with open('cmd.txt','r') as file:
        lines = file.readlines()
    yaml = YAML()
    yaml.indent(mapping=2,sequence=4,offset=2)
    i = 1
    for line in lines:
        uuid = generate_adversary_id()
        parts = line.strip().split('-->')
        technique_used = line[:5]
        tactic_used = lookup_tactic(technique_used)
        data = [{
        'technique_id': parts[0].strip(),
        'privilege': '',
        'buckets': [],
        'delete_payload': True,
        'description': 'Generated from SCYTHE',
        'technique_name': parts[0].strip(),
        'additional_info': {
            'cleanup': '[]'
        },
        'repeatable': False,
        'executors': [
            {
                'payloads': [],
                'code': None,
                'variations': [],
                'command': parts[1].strip(),
                'additional_info': {},
                'build_target': None,
                'uploads': [],
                'parsers': [],
                'timeout': 60,
                'cleanup': [],
                'platform': 'windows',
                'language': None,
                'name': 'cmd'
            }
        ],
        'requirements': [],
        'plugin': '',
        'singleton': True,
        'access': {},
        'name': tactic_used + f' {i}',
        'tactic': tactic_used,
        'id': uuid
        }]

        if os.path.exists('output.yaml'):
            os.remove('output.yaml')

        with open('output.yaml', 'w') as output_file:
            yaml.dump(data, output_file)

        with open('output.yaml','r') as yaml_file:
            lines = yaml_file.readlines()
        
        modified_lines = [line[2:] if line.startswith("  ") else line for line in lines]
        with open(f'abilities/{uuid}.yml', 'w') as file:
            file.writelines(modified_lines)

        uuid_list.append(uuid)
        i += 1

def generate_adversary(name, desc):
    yaml = YAML()
    yaml.indent(mapping=2,sequence=4,offset=2)
    adversary_id = generate_adversary_id()
    objective_id = generate_adversary_id()
    data = {
        'adversary_id': adversary_id,
        'name':name + ' (Generated from SCYTHE)',
        'description':desc,
        'atomic_ordering': [uuid.rstrip(":") for uuid in uuid_list],
        'objective': objective_id,
        'tags':[]
    }
    if os.path.exists('final.yaml'):
            os.remove('final.yaml')
    with open('final.yaml', 'w') as output_file:
        yaml.dump(data, output_file)

    with open('final.yaml','r') as yaml_file:
        lines = yaml_file.readlines()
        
    modified_lines = [line[2:] if line.startswith("  ") else line for line in lines]
    with open(f'adversaries/{adversary_id}.yml', 'w') as file:
        file.writelines(modified_lines)

def main():
    if len(sys.argv) != 2:
        print("Please provide the JSON input file.")
        print("Usage: python3 scrape.py <scythe_json_file>")
        sys.exit(1)

    json_file = sys.argv[1]

    adversary_name, description = scrape_json(json_file)
    create_directories()

    generate_abilities()
    generate_adversary(adversary_name, description)
    print("[+] Generated!")

    os.remove('final.yaml')
    os.remove('output.yaml')
    os.remove('cmd.txt')

if __name__ == '__main__':
    main()