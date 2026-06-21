import json
with open('pipeline_output/causal_inference_output.json') as f:
    d = json.load(f)

found = False
for inc in d['incidents']:
    for e in inc['events']:
        if '1/1/7' in e['message']:
            print(f"{inc['incident_id']}: {e['message']}")
            found = True

if not found:
    print("Not found in causal_inference_output.json!")

print("--- Preprocessed Events ---")
with open('pipeline_output/preprocessed_events.json') as f:
    d2 = json.load(f)
for e in d2:
    if '1/1/7' in e['message']:
        print(f"UID: {e['event_uid']} Subtype: {e['subtype']} Message: {e['message']}")
