import json
from datetime import timedelta
import networkx as nx
from timeline_reconstruction import event_time, compatibility_score, COMPAT_THRESHOLD

def debug_candidate_pairs(events, max_window, topo):
    print(f"debug_candidate_pairs called with {len(events)} events")
    for i in range(len(events)):
        try:
            ta = event_time(events[i])
        except KeyError as err:
            print(f"FAILED on events[{i}]:")
            print(events[i])
            raise err
    print("All event_time checks passed!")

def debug_pipeline():
    from preprocessing import load_data, restore_datetime_fields
    from timeline_reconstruction import normalize_domain, extract_port
    from topology_extraction import extract_topology

    raw = load_data('pipeline_output/preprocessed_events.json')
    norm = restore_datetime_fields(raw)
    
    for e in norm:
        e["incident_domain"] = normalize_domain(e)
        e["interface_id"] = e.get("interface_id") or extract_port(e)
        
    norm = sorted(norm, key=event_time)
    
    # Simulate integrated_pipeline
    topo_events = restore_datetime_fields(load_data('pipeline_output/preprocessed_events.json'))
    topo = extract_topology(topo_events)
    
    print("Calling build_compatibility_graph...")
    # Simulate build_compatibility_graph
    G = nx.Graph()
    for e in norm:
        G.add_node(e["event_uid"], **e)
        
    debug_candidate_pairs(norm, timedelta(seconds=1800), topo)

if __name__ == '__main__':
    debug_pipeline()
