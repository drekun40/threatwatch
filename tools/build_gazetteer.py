"""Build each site's `nearby:` list in config/facilities.yaml from US Census TIGER roads.

A news story often places an incident by street ("shots fired near Perry and Illinois") without naming
the site. `nearby:` terms let the matcher tie such a story to the site, with Buffalo context required
and a lower score than a direct name match (see Matcher and scoring).

  - a street near only this site is a term on its own ("Perry Street", "Perry St")
  - an intersection counts when two streets actually meet within `CROSS_M` of the site
    ("Main and Perry", "Perry & Main", "Main at Perry"); this is how arterials such as Main or
    Delaware, which pass many sites, still help without matching on their own
  - highway designations (State Rte 5, Interstate 190, the Skyway) are dropped

Run:  .venv/bin/python tools/build_gazetteer.py            (prints the lists)
      .venv/bin/python tools/build_gazetteer.py --write    (writes them into facilities.yaml)
Review the result: coordinates are approximate and street lists are a starting point.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
import time
from datetime import date
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
FAC = ROOT / "config" / "facilities.yaml"
TIGER = "https://tigerweb.geo.census.gov/arcgis/rest/services/TIGERweb/Transportation/MapServer"
LAYERS = (8, 6, 2)          # local roads, secondary roads, primary roads
SKIP = re.compile(r"\b(Interstate|I-\s*\d+|State Rte|State Hwy|US Hwy|Rte \d|Skwy|Ramp|Expy|Thruway|Exit)\b", re.I)
NEAR_M, CROSS_M = 250, 175     # standalone streets within NEAR_M; intersections within CROSS_M
SUFFIX = {"St": "Street", "Ave": "Avenue", "Rd": "Road", "Dr": "Drive", "Blvd": "Boulevard", "Pl": "Place",
          "Pkwy": "Parkway", "Ct": "Court", "Ln": "Lane", "Ter": "Terrace", "Sq": "Square", "Plz": "Plaza",
          "Way": "Way", "Aly": "Alley", "Cir": "Circle", "Hwy": "Highway"}
PREFIX = {"N": "North", "S": "South", "E": "East", "W": "West"}


def meters(a: tuple[float, float], b: tuple[float, float]) -> float:
    dy = (a[0] - b[0]) * 111_320
    dx = (a[1] - b[1]) * 111_320 * math.cos(math.radians(a[0]))
    return math.hypot(dx, dy)


def roads_near(lat: float, lon: float, radius_m: int) -> dict[str, list[tuple[float, float]]]:
    """Street name -> every vertex of its segments within radius_m (lat, lon), highways dropped."""
    out: dict[str, list] = {}
    for layer in LAYERS:
        r = requests.get(f"{TIGER}/{layer}/query", timeout=60, params={
            "geometry": f"{lon},{lat}", "geometryType": "esriGeometryPoint", "inSR": 4326, "distance": radius_m,
            "units": "esriSRUnit_Meter", "spatialRel": "esriSpatialRelIntersects", "outFields": "NAME",
            "returnGeometry": "true", "outSR": 4326, "f": "json"})
        r.raise_for_status()
        for f in r.json().get("features", []):
            name = (f["attributes"].get("NAME") or "").strip()
            if not name or SKIP.search(name):
                continue
            pts = [(round(y, 6), round(x, 6)) for path in f.get("geometry", {}).get("paths", []) for x, y in path]
            out.setdefault(name, []).extend(pts)
        time.sleep(0.3)
    return out


def crossings(streets: dict[str, list], site: tuple[float, float]) -> dict[tuple[str, str], float]:
    """Pairs of differently named streets that share a vertex (TIGER segments meet at intersections)
    within CROSS_M of the site -> distance in metres from the site to that intersection."""
    at: dict[tuple, set[str]] = {}
    for name, pts in streets.items():
        for p in pts:
            if meters(p, site) <= CROSS_M:
                at.setdefault(p, set()).add(name)
    pairs: dict[tuple[str, str], float] = {}
    for p, names in at.items():
        for a in names:
            for b in names:
                if a != b:
                    pairs[(a, b)] = min(pairs.get((a, b), 1e9), meters(p, site))
    return pairs


# street names found in most towns: on their own they don't place a story in Buffalo (a Batavia story
# on "North Street" carries a Buffalo station's dateline); they still count inside an intersection
COMMON = set("""Main Church North South East West High Elm Oak Pine Maple Cedar Park Washington Lincoln Jefferson
Franklin Center Union Mill Mills Water Spring Market Court Clinton Wilson William Charles Mark Best Summer
Pearl Erie Front Bridge School Chestnut Walnut Ridge Lake Hill Prospect Jackson Madison Adams Grant Monroe
Fillmore Delaware Niagara Seneca Broadway Liberty Railroad Canal Elmwood Highland Grove Forest Willow""".split())


def standalone_ok(name: str) -> bool:
    words = name.split()
    base = expand(name)[0]
    return len(words) > 1 and words[-1] in SUFFIX and len(base) > 2 and base not in COMMON


def expand(name: str) -> tuple[str, list[str]]:
    """'S Park Ave' -> ('South Park', ['South Park Avenue', 'South Park Ave', 'S Park Ave'])."""
    name = re.sub(r"\bO([a-z])", lambda m: "O'" + m.group(1).upper(), name)   # TIGER drops the apostrophe
    words = name.split()
    if words and words[0] in PREFIX:
        words[0] = PREFIX[words[0]]
    suffix = words[-1] if len(words) > 1 and words[-1] in SUFFIX else ""
    base = " ".join(words[:-1] if suffix else words)
    forms = {name}
    if suffix:
        forms |= {f"{base} {SUFFIX[suffix]}", f"{base} {suffix}"}
    return base, sorted(forms)


def build(facilities: list[dict]) -> dict[str, list[str]]:
    near, cross = {}, {}
    for f in facilities:
        site = (f["lat"], f["lon"])
        streets = roads_near(*site, NEAR_M)
        near[f["id"]] = set(streets)
        cross[f["id"]] = crossings(streets, site)
        print(f"  {f['id']}: {len(streets)} streets, {len(cross[f['id']]) // 2} intersections", file=sys.stderr)
    sites_per_street: dict[str, int] = {}
    for streets in near.values():
        for s in streets:
            sites_per_street[s] = sites_per_street.get(s, 0) + 1
    # an intersection belongs only to the site nearest to it, so one corner downtown doesn't put a
    # story at nine sites at once
    nearest: dict[tuple[str, str], str] = {}
    for fid, pairs in cross.items():
        for pair, d in pairs.items():
            if pair not in nearest or d < cross[nearest[pair]][pair]:
                nearest[pair] = fid
    out = {}
    for fid in near:
        terms = set()
        for s in near[fid]:
            if sites_per_street[s] == 1 and standalone_ok(s):
                terms |= set(expand(s)[1])
        for a, b in (pair for pair in cross[fid] if nearest[pair] == fid):
            ba, bb = expand(a)[0], expand(b)[0]
            if len(ba) > 2 and len(bb) > 2 and ba != bb:
                terms |= {f"{ba} and {bb}", f"{ba} & {bb}", f"{ba} at {bb}"}
        out[fid] = sorted(terms, key=str.lower)
    return out


def write(lists: dict[str, list[str]]) -> None:
    """Insert or replace one `nearby:` line per facility, keeping every comment in the file."""
    lines = FAC.read_text().splitlines()
    out, fid = [], None
    stamp = f"  # streets near this site only, and intersections; generated {date.today()} from Census TIGER, review"
    for line in lines:
        m = re.match(r"\s*- id:\s*(\S+)", line)
        if m:
            fid = m.group(1)
        if re.match(r"\s+nearby:", line):        # replaced below
            continue
        out.append(line)
        if fid in lists and re.match(r"\s+ambiguous:", line):
            indent = re.match(r"(\s+)", line).group(1)
            out.append(f"{indent}nearby: {yaml.safe_dump(lists[fid], default_flow_style=True, width=10**6).strip()}{stamp}")
    FAC.write_text("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    facilities = yaml.safe_load(FAC.read_text())["facilities"]
    lists = build(facilities)
    for fid, terms in lists.items():
        print(f"{fid} ({len(terms)}): {', '.join(t for t in terms if ' & ' not in t and ' at ' not in t)}")
    if args.write:
        write(lists)
        print(f"wrote nearby: lists to {FAC}")


if __name__ == "__main__":
    main()
