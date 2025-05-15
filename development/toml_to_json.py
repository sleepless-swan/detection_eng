import requests
import os
import tomllib


url = ""
api_key = os.environ['ELASTIC_KEY']
headers ={
    'content-type': 'application/json;charset=UTF-8',
    'kbn-xsrf' : 'true',
    'Authorization' : 'ApiKey '+ api_key 
}

data = ""

for root, dirs, files in os.walk(""):
    for file in  files:

        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                
                if alert['rule']['type'] == "query": #query based alert
                    required_fields = ['author', 'description', 'name', 'risk_score', 'severity','type ', 'query' ]
                elif alert['rule']['type'] == "eql": #event correlation alert
                    required_fields = ['author', 'description', 'name', 'risk_score', 'severity','type ', 'query', 'language' ]
                elif alert['rule']['type'] == "threshold": #threshold based alert
                    required_fields = ['author','description', 'name', 'risk_score', 'severity','type ', 'query', 'threshold' ]
                else:
                    print("unsupported file type found in " + full_path)
                    break
                
                for field in alert['rule']:
                    if field in required_fields:
                        if type (alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'", "\"") + "," + "\n"
                        elif type (alert['rule'][field]) == str:
                            data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"", "\\\"") + "\"," + "\n"
                        elif type (alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                data += "  \"enabled\": true\n}"

            elastic_data = requests.post(url, headers=headers, data=data).json()
            print(elastic_data)
