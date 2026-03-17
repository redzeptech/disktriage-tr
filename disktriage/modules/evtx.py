from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True, slots=True)
class EvtxEvent:
    channel: str
    provider: str
    event_id: int
    level: Optional[int]
    time_created_utc: Optional[str]
    computer: Optional[str]
    data: Dict[str, str]


def _decode_best_effort(b: bytes) -> str:
    if not b:
        return ""

    candidates: List[str] = []
    for enc in ("utf-8", "utf-16", "mbcs"):
        try:
            candidates.append(b.decode(enc, errors="replace"))
        except Exception:
            continue

    if not candidates:
        return ""

    def score(s: str) -> Tuple[int, int]:
        # Prefer fewer replacement chars and more non-whitespace.
        return (s.count("\ufffd"), -len(s.strip()))

    return sorted(candidates, key=score)[0]


def _one_line(s: str) -> str:
    return " ".join((s or "").replace("\r", "\n").split())


def _run_wevtutil(args: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(args, capture_output=True)
    out = _decode_best_effort(p.stdout)
    err = _decode_best_effort(p.stderr)
    return p.returncode, out, err


def _parse_wevtutil_xml(xml_text: str) -> List[EvtxEvent]:
    xml_text = (xml_text or "").strip()
    if not xml_text:
        return []

    # wevtutil outputs multiple <Event> documents. Wrap into a root.
    wrapped = "<Events>\n" + xml_text + "\n</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return []

    events: List[EvtxEvent] = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    for ev in root.findall("e:Event", ns):
        system = ev.find("e:System", ns)
        if system is None:
            continue

        channel = (system.findtext("e:Channel", default="", namespaces=ns) or "").strip()
        provider = ""
        provider_el = system.find("e:Provider", ns)
        if provider_el is not None:
            provider = (provider_el.attrib.get("Name") or "").strip()

        event_id_raw = system.findtext("e:EventID", default="0", namespaces=ns)
        try:
            event_id = int(event_id_raw)
        except Exception:
            event_id = 0

        level_raw = system.findtext("e:Level", default="", namespaces=ns)
        try:
            level = int(level_raw) if level_raw != "" else None
        except Exception:
            level = None

        computer = system.findtext("e:Computer", default="", namespaces=ns) or None

        time_created_utc = None
        tc = system.find("e:TimeCreated", ns)
        if tc is not None:
            time_created_utc = tc.attrib.get("SystemTime")

        data: Dict[str, str] = {}
        event_data = ev.find("e:EventData", ns)
        if event_data is not None:
            for d in event_data.findall("e:Data", ns):
                name = d.attrib.get("Name") or ""
                value = (d.text or "").strip()
                if name:
                    data[name] = value

        user_data = ev.find("e:UserData", ns)
        if user_data is not None and not data:
            # If EventData is empty, still try to capture leaf texts.
            for node in user_data.iter():
                if node is user_data:
                    continue
                if node.text and node.text.strip():
                    data[node.tag.rsplit("}", 1)[-1]] = node.text.strip()

        events.append(
            EvtxEvent(
                channel=channel,
                provider=provider,
                event_id=event_id,
                level=level,
                time_created_utc=time_created_utc,
                computer=computer,
                data=data,
            )
        )

    return events


def _query_events(
    *,
    log_or_path: str,
    xpath_query: str,
    max_events: int,
    from_file: bool,
) -> Tuple[List[EvtxEvent], Optional[str]]:
    args = ["wevtutil", "qe", log_or_path, "/q:" + xpath_query, "/f:xml", f"/c:{int(max_events)}", "/rd:true"]
    if from_file:
        args.append("/lf:true")

    rc, out, err = _run_wevtutil(args)
    if rc != 0:
        msg = _one_line(err).strip() or f"wevtutil hata kodu: {rc}"
        return [], msg
    return _parse_wevtutil_xml(out), None


def collect_event_logs(
    *,
    days: int = 7,
    max_events: int = 50,
    include_security: bool = True,
    evtx_path: Optional[str] = None,
) -> Dict[str, Any]:
    # Uses wevtutil. Supports live logs or offline .evtx via /lf:true.
    result: Dict[str, Any] = {
        "enabled": True,
        "source": "wevtutil",
        "days": int(days),
        "system_critical_errors": [],
        "security_logons": {"events": [], "summary": {}},
        "errors": [],
    }

    timediff_ms = int(days) * 24 * 60 * 60 * 1000

    from_file = bool(evtx_path)
    log_target = evtx_path if evtx_path else "System"

    # System: Critical (1) or Error (2)
    sys_query = f"*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= {timediff_ms}]]]"
    sys_events, sys_err = _query_events(
        log_or_path=log_target,
        xpath_query=sys_query,
        max_events=max_events,
        from_file=from_file,
    )
    if sys_err:
        result["errors"].append(f"System: {sys_err}")
    else:
        result["system_critical_errors"] = [asdict(e) for e in sys_events]

    if include_security and not from_file:
        sec_query = f"*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= {timediff_ms}]]]"
        sec_events, sec_err = _query_events(
            log_or_path="Security",
            xpath_query=sec_query,
            max_events=max_events,
            from_file=False,
        )
        if sec_err:
            result["errors"].append(f"Security: {sec_err}")
        else:
            result["security_logons"]["events"] = [asdict(e) for e in sec_events]

            success = 0
            failure = 0
            by_user: Dict[str, int] = {}
            by_ip: Dict[str, int] = {}

            for e in sec_events:
                if e.event_id == 4624:
                    success += 1
                elif e.event_id == 4625:
                    failure += 1

                user = e.data.get("TargetUserName") or e.data.get("SubjectUserName") or ""
                ip = e.data.get("IpAddress") or e.data.get("WorkstationName") or ""

                if user:
                    by_user[user] = by_user.get(user, 0) + 1
                if ip:
                    by_ip[ip] = by_ip.get(ip, 0) + 1

            def top(d: Dict[str, int], n: int = 10) -> List[Dict[str, Any]]:
                return [{"key": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]]

            result["security_logons"]["summary"] = {
                "success_count": success,
                "failure_count": failure,
                "top_users": top(by_user, 10),
                "top_sources": top(by_ip, 10),
            }

    return result

