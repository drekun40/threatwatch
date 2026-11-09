"""Small geo helpers (no external dependencies)."""
from __future__ import annotations

import math


def km_between(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def facilities_near(lat: float, lon: float, facilities: list[dict] | dict, buffer_km: float = 0.15) -> list[tuple[str, float]]:
    """Facilities whose geofence (radius_km + buffer) contains the point, nearest first."""
    items = facilities.values() if isinstance(facilities, dict) else facilities
    out = []
    for f in items:
        if f.get("lat") is None:
            continue
        d = km_between(lat, lon, f["lat"], f["lon"])
        if d <= float(f.get("radius_km", 0.5)) + buffer_km:
            out.append((f["id"], d))
    return sorted(out, key=lambda x: x[1])


def nearest_facility(lat: float, lon: float, facilities, max_km: float) -> tuple[str, float] | None:
    items = facilities.values() if isinstance(facilities, dict) else facilities
    best = None
    for f in items:
        d = km_between(lat, lon, f["lat"], f["lon"])
        if d <= max_km and (best is None or d < best[1]):
            best = (f["id"], d)
    return best


# Buffalo Niagara International Airport — low-altitude traffic near it is normal approach/departure.
BUF_AIRPORT = (42.9405, -78.7322)
