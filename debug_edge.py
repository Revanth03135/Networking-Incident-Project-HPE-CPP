import json
import sys
sys.path.append('causalInference')
import causalInference

with open('pipeline_output/timeline_output.json') as f:
    d = json.load(f)

inc = None
for i in d:
    if i['incident_id'] == 'INC-0002':
        inc = i
        break

normalized = []
for i, e in enumerate(inc['events'], 1):
    x = dict(e)
    x["event_uid"] = i
    x["normalized_subtype"] = causalInference.subtype(x)
    x["normalized_domain"] = causalInference.domain(x)
    x["root_score"] = causalInference.root_score(x, i, len(inc['events']))
    x["actionable"] = causalInference.is_actionable(x)
    x["is_recovery"] = causalInference.is_recovery(x)
    normalized.append(x)

non_recovery = [e for e in normalized if not e["is_recovery"]]
a = next(e for e in non_recovery if e['event_uid'] == 2)
b = next(e for e in non_recovery if e['event_uid'] == 4)

print("a:", a)
print("b:", b)
print("relation:", causalInference.relation(a, b))
