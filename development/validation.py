import tomllib
import sys
import os

#file = "alert_example.toml"

for root, dirs, files in os.walk(""):
    for file in  files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)



                present_fields = []
                missing_fields = []

                if alert['rule']['type'] == "query": #query based alert
                    required_fields = ['description', 'name', 'risk_score', 'severity','type ', 'query' ]
                elif alert['rule']['type'] == "eql": #event correlation alert
                    required_fields = ['description', 'name', 'risk_score', 'severity','type ', 'query', 'language' ]
                elif alert['rule']['type'] == "threshold": #threshold based alert
                    required_fields = ['description', 'name', 'risk_score', 'severity','type ', 'query', 'threshold' ]
                else:
                    print("unsupported file type found in "+full_path)
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print("the following fields do not exist in " + file + ": " + str(missing_fields))
                else:
                    print("Vaildation passed for: " + file)