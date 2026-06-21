import sys, json
sys.path.append('causalInference')
from causalInference import relation, parse_dt, get_time, subtype, domain, port, LAYER, text
events = next(i['events'] for i in json.load(open('pipeline_output/timeline_output.json')) if i['incident_id'] == 'INC-0002')
e16 = next(e for e in events if e['event_uid'] == 16)
e20 = next(e for e in events if e['event_uid'] == 20)
print('score:', relation(e16, e20))
