
import requests

url = ""
id=""
full_path = url+ id
api_key = ""
headers ={
    'content-type': 'application/json;charset=UTF-8',
    'kbn-xsrf' : 'true',
    'Authorization' : 'ApiKey '+ api_key 
}



elastic_data = requests.get(full_path, headers=headers).json()
print(elastic_data)