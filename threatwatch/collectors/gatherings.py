"""Planned public gatherings near the sites (rallies, marches, vigils, town halls), from Mobilize's
public events API. Free, no key.

Like Ticketmaster events these are crowd context, not threats: a lawful demonstration is not a threat
item. A gathering within `max_km` of a site goes into the events table, so the dashboard lists it, a
threat item at that site within ±6 h gets the event bonus, and hourly mode runs full scans around it.
Only the event itself is kept (title, type, time, place, link): no organiser contacts, no attendees.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import http
from ..geo import nearest_facility
from ..models import Post, utcnow
from . import CollectContext

URL = "https://api.mobilize.us/v1/events"
UA = "ThreatWatch/0.3 (facility security monitoring)"
# in-person event types that draw a crowd; phone banks, trainings, fundraisers etc. are left out
CROWD_TYPES = ["RALLY", "VISIBILITY_EVENT", "SOLIDARITY_EVENT", "TOWN_HALL", "COMMUNITY", "MARCH", "OTHER"]
LABEL = {"VISIBILITY_EVENT": "Demonstration", "SOLIDARITY_EVENT": "Solidarity event", "TOWN_HALL": "Town hall",
         "RALLY": "Rally", "MARCH": "March", "COMMUNITY": "Community event", "OTHER": "Public event"}


def parse_gathering(ev: dict, slot: dict, facilities: list, max_km: float, crowd: set) -> dict | None:
    if ev.get("is_virtual") or ev.get("visibility") != "PUBLIC" or ev.get("event_type") not in crowd:
        return None
    loc = ev.get("location") or {}
    geo = loc.get("location") or {}
    try:
        lat, lon = float(geo["latitude"]), float(geo["longitude"])
    except (KeyError, TypeError, ValueError):
        return None                       # private address: nothing to place
    near = nearest_facility(lat, lon, facilities, max_km=max_km)
    if not near or not slot.get("start_date"):
        return None
    when = datetime.fromtimestamp(int(slot["start_date"]), tz=timezone.utc)
    venue = ", ".join(x for x in (loc.get("venue"), " ".join(loc.get("address_lines") or []).strip(),
                                  loc.get("locality")) if x)
    return {"id": f"mobilize:{ev['id']}:{slot.get('id', slot['start_date'])}", "source": "mobilize",
            "name": f"{LABEL.get(ev['event_type'], 'Public event')}: {ev.get('title', '').strip()}"[:200],
            "venue": venue[:200], "facility_id": near[0], "start_at": when.isoformat(),
            "url": ev.get("browser_url", ""), "lat": lat, "lon": lon,
            "info": {"segment": "Public gathering", "type": ev["event_type"]}}


class GatheringsCollector:
    name = "gatherings"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def collect(self, ctx: CollectContext) -> list[Post]:
        now = utcnow()
        until = now + timedelta(days=int(self.cfg.get("days_ahead", 14)))
        crowd = set(self.cfg.get("event_types", CROWD_TYPES))
        facs = ctx.facilities.get("facilities", [])
        seen, stored = set(), 0
        for zipcode in self.cfg.get("zipcodes", ["14202"]):
            params = {"zipcode": zipcode, "max_dist": int(self.cfg.get("max_dist_miles", 10)),
                      "timeslot_start": f"gte_{int((now - timedelta(hours=6)).timestamp())}",
                      "timeslot_end": f"lte_{int(until.timestamp())}", "per_page": 100}
            r = http.get(URL, params=params, headers={"User-Agent": UA}, timeout=30)
            r.raise_for_status()
            for ev in r.json().get("data", []):
                for slot in ev.get("timeslots") or []:
                    e = parse_gathering(ev, slot, facs, float(self.cfg.get("max_km", 1.0)), crowd)
                    if e and e["id"] not in seen and now - timedelta(hours=6) <= datetime.fromisoformat(e["start_at"]) <= until:
                        seen.add(e["id"])
                        ctx.store.upsert_event(e)
                        stored += 1
        ctx.store.commit()
        ctx.store.set_state("gatherings_last_count", stored)
        return []   # context only, like Ticketmaster events
