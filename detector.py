import math
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse

THRESHOLDS = {
    "long_query": 55,
    "long_label": 35,
    "label_entropy": 3.5,
    "subdomain_count": 4,
    "frequency": 20,
    "unique_subdomains": 15
}

def entropy(value):
    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 3)

def normalize_domain(value):
    value = str(value or "").strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0]
    return value

def registered_domain(domain):
    labels = normalize_domain(domain).split(".")
    labels = [label for label in labels if label]
    if len(labels) <= 2:
        return ".".join(labels)
    common_two_part_suffixes = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "firm.in", "net.in", "org.in", "gen.in", "ac.in", "edu.in", "gov.in", "co.nz", "com.br", "com.cn", "com.sg", "co.jp"}
    suffix = ".".join(labels[-2:])
    if suffix in common_two_part_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def label_looks_encoded(label):
    if len(label) < 12:
        return False
    compact = label.lower()
    hex_like = re.fullmatch(r"[0-9a-f]+", compact) is not None and len(compact) >= 16
    base32_like = re.fullmatch(r"[a-z2-7]+=*", compact) is not None and len(compact.rstrip("=")) >= 16
    mixed_like = re.fullmatch(r"[a-z0-9_-]+", compact) is not None and len(compact) >= 24 and len(set(compact)) >= 8
    return hex_like or base32_like or mixed_like

def prepare_records(records):
    cleaned = []
    for index, source in enumerate(records):
        domain = normalize_domain(source.get("domain") or source.get("query") or source.get("queried_domain") or "")
        if not domain:
            continue
        labels = domain.split(".")
        timestamp = str(source.get("timestamp") or source.get("time") or "")
        if not timestamp:
            timestamp = datetime_fallback(index)
        cleaned.append({
            "timestamp": timestamp,
            "source_ip": str(source.get("source_ip") or source.get("src_ip") or "Unknown"),
            "destination_ip": str(source.get("destination_ip") or source.get("dst_ip") or "Unknown"),
            "domain": domain,
            "record_type": str(source.get("record_type") or source.get("qtype") or "A").upper(),
            "registered_domain": registered_domain(domain)
        })
    return cleaned

def datetime_fallback(index):
    return f"Sample record {index + 1}"

def detect_queries(records):
    cleaned = prepare_records(records)
    domain_counts = Counter(item["registered_domain"] for item in cleaned)
    unique_by_domain = defaultdict(set)
    for item in cleaned:
        subdomain = item["domain"]
        base = item["registered_domain"]
        if subdomain != base and subdomain.endswith("." + base):
            unique_by_domain[base].add(subdomain[:-len(base)-1])
    analyzed = []
    for record_id, item in enumerate(cleaned):
        domain = item["domain"]
        base = item["registered_domain"]
        labels = domain.split(".")
        subdomain_labels = labels[:-len(base.split("."))] if base else labels[:-2]
        longest_label = max((len(label) for label in labels), default=0)
        max_entropy = max((entropy(label) for label in subdomain_labels), default=0.0)
        reasons = []
        triggered = []
        score = 0
        def add(rule, points, reason):
            nonlocal score
            triggered.append(rule)
            reasons.append(reason)
            score += points
        if len(domain) >= THRESHOLDS["long_query"]:
            add("long_query", 20, f"Query name is long ({len(domain)} characters).")
        if longest_label >= THRESHOLDS["long_label"]:
            add("long_label", 20, f"At least one label is long ({longest_label} characters).")
        if max_entropy >= THRESHOLDS["label_entropy"] and any(len(label) >= 10 for label in subdomain_labels):
            add("high_entropy", 25, f"A subdomain label has high character entropy ({max_entropy:.3f}).")
        if len(subdomain_labels) >= THRESHOLDS["subdomain_count"]:
            add("deep_subdomains", 10, f"Query contains {len(subdomain_labels)} subdomain labels.")
        if label_looks_encoded("".join(subdomain_labels)):
            add("encoded_pattern", 20, "Subdomain contains a long encoded-looking character sequence.")
        if domain_counts[base] >= THRESHOLDS["frequency"]:
            add("frequent_domain", 15, f"The dataset contains {domain_counts[base]} queries for this registered domain.")
        if len(unique_by_domain[base]) >= THRESHOLDS["unique_subdomains"]:
            add("many_unique_subdomains", 20, f"The dataset contains {len(unique_by_domain[base])} unique subdomains for this registered domain.")
        score = min(score, 100)
        severity = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        analyzed.append({
            **item,
            "record_id": record_id,
            "query_length": len(domain),
            "entropy": max_entropy,
            "triggered_rules": triggered,
            "reasons": reasons if reasons else ["No configured detection rules were triggered."],
            "risk_score": score,
            "severity": severity
        })
    return analyzed
