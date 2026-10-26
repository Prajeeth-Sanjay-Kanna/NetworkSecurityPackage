import csv
import io
import os
from datetime import datetime, timezone

REQUIRED_COLUMNS = {"domain"}

def analyze_csv(source):
    close_after = False
    if isinstance(source, (str, os.PathLike)):
        handle = open(source, "r", encoding="utf-8-sig", newline="")
        close_after = True
    elif hasattr(source, "read"):
        raw = source.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8-sig")
        handle = io.StringIO(raw)
    else:
        raise ValueError("Unsupported CSV input.")
    try:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV file must contain a header row.")
        normalized = {name.strip().lower(): name for name in reader.fieldnames if name}
        domain_column = next((normalized[key] for key in ("domain", "query", "queried_domain", "qname") if key in normalized), None)
        if not domain_column:
            raise ValueError("CSV needs a domain, query, queried_domain, or qname column.")
        records = []
        for row in reader:
            domain = (row.get(domain_column) or "").strip()
            if not domain:
                continue
            def value(*names, default=""):
                for name in names:
                    actual = normalized.get(name)
                    if actual and row.get(actual):
                        return row[actual].strip()
                return default
            records.append({
                "timestamp": value("timestamp", "time", "datetime", default=""),
                "source_ip": value("source_ip", "src_ip", "source", default="Unknown"),
                "destination_ip": value("destination_ip", "dst_ip", "destination", default="Unknown"),
                "domain": domain,
                "record_type": value("record_type", "qtype", "type", default="A")
            })
        if not records:
            raise ValueError("No DNS query rows with a domain were found in the CSV.")
        return records
    except csv.Error as exc:
        raise ValueError("CSV parsing failed. Check the file format.") from exc
    finally:
        if close_after:
            handle.close()

def analyze_pcap(source):
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, PcapReader
    except ImportError as exc:
        raise ImportError("Scapy is required to analyze PCAP files.") from exc
    records = []
    try:
        reader = PcapReader(source)
        with reader:
            for packet in reader:
                if DNS not in packet or DNSQR not in packet:
                    continue
                dns = packet[DNS]
                if getattr(dns, "qr", 1) != 0:
                    continue
                query = packet[DNSQR].qname
                if isinstance(query, bytes):
                    query = query.decode("utf-8", errors="replace")
                source_ip = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "Unknown"
                destination_ip = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else "Unknown"
                record_type = str(getattr(packet[DNSQR], "qtype", 1))
                records.append({
                    "timestamp": datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(),
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "domain": str(query),
                    "record_type": record_type
                })
    except Exception as exc:
        raise ValueError("Could not parse this packet capture. Verify that it is a valid PCAP or PCAPNG file.") from exc
    if not records:
        raise ValueError("No DNS queries were found in this packet capture.")
    return records
