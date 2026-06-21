from preprocessing import load_data, restore_datetime_fields
from timeline_reconstruction import normalize_domain, extract_port, event_time

raw = load_data('pipeline_output/preprocessed_events.json')
is_preprocessed = raw and isinstance(raw[0], dict) and 'corrected_time' in raw[0]
print(f'is_preprocessed: {is_preprocessed}')

norm = restore_datetime_fields(raw)
print(f'After restore: {len(norm)} events')
has_ct = 'corrected_time' in norm[0]
print(f'Has corrected_time: {has_ct}')
print(f'Type: {type(norm[0].get("corrected_time"))}')

# Now annotate
for e in norm:
    e['incident_domain'] = normalize_domain(e)
    e['interface_id'] = e.get('interface_id') or extract_port(e)

has_ct2 = 'corrected_time' in norm[0]
print(f'After annotation: corrected_time still there: {has_ct2}')

# Now sort
norm = sorted(norm, key=event_time)
print(f'After sort: {len(norm)} events')
print('SUCCESS - no KeyError')
