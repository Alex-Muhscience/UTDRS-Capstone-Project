"""
Delivers device scans to the API gateway.

The scanner server stores each scan it accepts. The processor turns those into the
gateway's scan reports and posts them, so a scanned device appears in UTDRS as an
asset, and as an event when it is new or its inventory has changed.
"""
import json
import urllib.error
import urllib.request

# Worth trying again later: the gateway is unreachable, overloaded or not yet configured
# with our token. Anything else it rejects will be rejected every time.
RETRYABLE_STATUSES = {401, 403, 408, 429}


class RetryLater(Exception):
    """The scan could not be delivered now; leave it where it is and try again."""


def scan_to_report(doc):
    """
    The gateway's scan report for a document from the scanner server's `scans` collection.

    Raises ValueError when the document is not a scan the gateway could accept.
    """
    scan = doc.get('scan')
    if not isinstance(scan, dict):
        raise ValueError("document has no scan")
    for field in ('hostname', 'os', 'timestamp'):
        if not isinstance(scan.get(field), str) or not scan[field]:
            raise ValueError(f"scan has no {field}")

    interfaces = []
    for interface in scan.get('interfaces') or []:
        if isinstance(interface, dict) and interface.get('name'):
            interfaces.append({
                'name': interface['name'],
                'ip_address': interface.get('ip') or None,
                'mac_address': interface.get('mac') or None,
            })

    return {
        'hostname': scan['hostname'],
        'os': scan['os'],
        'os_version': scan.get('os_version') or None,
        'cpu_cores': scan.get('cpu_cores'),
        'memory_kb': scan.get('memory_kb'),
        'interfaces': interfaces,
        'timestamp': scan['timestamp'],
        'reported_from': doc.get('client_ip'),
        'scan_id': str(doc['_id']) if doc.get('_id') is not None else None,
    }


def deliver_scan(report, gateway_url, token, timeout=10):
    """Post a scan report to the gateway and return its answer."""
    request = urllib.request.Request(
        gateway_url.rstrip('/') + '/api/v1/scans/',
        data=json.dumps(report).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'X-Internal-Token': token or ''},
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', 'replace')[:500]
        e.close()
        if e.code >= 500 or e.code in RETRYABLE_STATUSES:
            raise RetryLater(f"gateway answered {e.code}: {detail}") from e
        raise ValueError(f"gateway rejected the scan ({e.code}): {detail}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RetryLater(f"gateway unreachable: {e}") from e
