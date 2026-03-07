import json

with open("report.json") as f:
    data = json.load(f)

# print detector names
for issue in data["results"]["detectors"]:
    print(issue["check"])