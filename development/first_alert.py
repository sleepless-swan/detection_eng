
import requests

url = ""
api_key = ""
headers ={
    'content-type': 'application/json;charset=UTF-8',
    'kbn-xsrf' : 'true',
    'Authorization' : 'ApiKey '+ api_key 
}

data = """
{
  "from": "now-70m",
  "name": "MS Office child process",
  "tags": [
    "child process",
    "ms office"
  ],
  "type": "query",
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "enabled": true,
  "filters": [
    {
      "query": {
        "match": {
          "event.action": {
            "type": "phrase",
            "query": "Process Create (rule: ProcessCreate)"
          }
        }
      }
    }
  ],
  "rule_id": "process_started_by_ms_office_program",
  "interval": "1h",
  "language": "kuery",
  "severity": "low",
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "required_fields": [
    {
      "name": "process.parent.name",
      "type": "keyword"
    }
  ],
  "related_integrations": [
    {
      "package": "o365",
      "version": "^2.3.2"
    }
  ]
}

"""

elastic_data = requests.post(url, headers=headers, data=data).json()
print(elastic_data)