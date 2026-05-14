import hashlib
from datetime import datetime, timezone


# =========================================================
# HELPERS
# =========================================================

def generate_uid(raw_log):

    return hashlib.sha1(
        raw_log.encode()
    ).hexdigest()


def current_ingestion_time():

    return datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# =========================================================
# MAIN FORMATTER
# =========================================================

def normalize_output(
    schema,
    raw_log
):

    return {

        "event": {

            "event_uid": schema.get(
                "event_uid"
            ) or generate_uid(raw_log),

            "event_id": schema.get(
                "event_id"
            ),

            "type": schema.get(
                "type"
            ),

            "subtype": schema.get(
                "subtype"
            ),

            "severity": schema.get(
                "severity"
            ),

            "message": schema.get(
                "message"
            )
        },

        "device": {

            "hostname": schema.get(
                "hostname"
            ),

            "ip": schema.get(
                "ip"
            ),

            "vendor": schema.get(
                "vendor"
            ),

            "os": schema.get(
                "os"
            )
        },

        "network": {

            "interface_id": schema.get(
                "interface_id"
            ),

            "vlan": schema.get(
                "vlan"
            )
        },

        "timestamps": {

            "event_time": schema.get(
                "event_time"
            ),

            "ingestion_time": current_ingestion_time()
        },

        "raw": {

            "message": raw_log
        }
    }