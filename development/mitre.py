import requests
import tomllib
import os


url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept': 'application/json',

}

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}

#def getMapping(mitreData):

for object in mitreData ['objects']:
    tactics = []
    if object ['type'] == 'attack-pattern':
        if 'external_references' in object:
            for reference in object ['external_references']:
                if 'external_id' in reference:
                    if ((reference['external_id'].startswith("T"))):
                        if 'kill_chain_phases' in object:
                            for tactic in object ['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        technique = reference ['external_id']
                        name = object['name']
                        url = reference ['url']
                        
                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                            filtered_object = {'tactics' : str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_object
                        else:
                            filtered_object = {'tactics' : str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': "False"}
                            mitreMapped[technique] = filtered_object

for root, dirs, files in os.walk(""):
    for file in  files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                

                if alert['rule']['threat'][0]['framework'] == "MITRE ATTACK":
                    for threat in alert['rule']['threat']:
                        technique_id = threat ['technique'][0]['id']
                        technique_name = ['technique'][0]['name']

                        print (file + " : " + technique_id + " : " + technique_name)