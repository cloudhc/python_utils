import json
import ndjson

data = ["TCP", "10.189.0.1", 89, "255.255.255.233", 443, 1024]

print(",".join(str(item) for item in data))

json_data = {}

json_data['protocol'] = data[0]
json_data['src_addr'] = data[1]
json_data['src_port'] = data[2]
json_data['dst_addr'] = data[3]
json_data['dst_port'] = data[4]
json_data['bytes'] = data[5]

print(json.dumps(json_data))
