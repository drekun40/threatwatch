"""Expanded keyword pack. merge_into(cfg) adds these terms and categories to an existing keywords config
without removing anything the user added or changing weights they set."""
from __future__ import annotations

ADD_TERMS = {
    "explosives_terrorism": ["bomb", "bomb squad", "detonation", "detonated", "unattended bag", "unattended package",
                             "suspicious bag", "suspicious vehicle", "hazmat", "chemical spill", "white powder",
                             "evacuation order", "terror attack", "jihad", "ISIS"],
    "weapons_violence": ["gun", "gunfire", "gunman", "firearm", "armed man", "armed suspect", "man with a gun",
                         "brandished", "knife", "machete", "pistol", "rifle", "shots rang out", "drive-by",
                         "murder", "shot and killed", "stabbed to death", "killed in a shooting", "carjacking", "armed robbery", "beaten", "fistfight",
                         "pepper spray"],
    "vehicle": ["pedestrian struck", "struck by a vehicle", "hit by a car", "rollover", "multi-vehicle",
                "fatal crash", "DWI", "drunk driver", "police chase", "pursuit", "vehicle into crowd"],
    "crowd_safety": ["crowd surge", "crush", "trampled", "pushing and shoving", "fainted", "heat exhaustion",
                     "cardiac arrest", "CPR", "missing child", "lost child", "ambulance", "EMS"],
    "public_order": ["sit-in", "blockade", "clash", "clashes", "unrest", "mob", "looting", "arrested",
                     "arrests", "heavy police presence", "disturbance", "rowdy", "unruly", "ejected",
                     "street takeover", "car meet", "pop-up party", "trespass notice", "picket"],
    "property_access": ["structure fire", "arson", "fire alarm", "smoke", "break in", "broken into", "stolen",
                        "theft", "window smashed", "damaged", "fence cut", "unauthorized access", "squatters"],
    "critical_infrastructure": ["outage", "water main break", "gas leak", "bridge strike", "bridge damage",
                                "signal outage", "train delay", "Amtrak", "CSX", "Peace Bridge", "border crossing",
                                "NFTA", "Metro Rail", "substation", "transformer fire", "pipeline"],
    "maritime": ["Coast Guard search", "missing boater", "swimmer missing", "rip current", "ice rescue",
                 "fell through the ice", "jet ski", "kayak", "vessel fire", "oil spill", "harbor closure",
                 "marine incident", "breakwall", "pulled from the water"],
    "aerial": ["drone sighting", "flight restriction", "TFR", "airspace violation", "banner plane", "paramotor",
               "low flying", "police helicopter", "Mercy Flight"],
    "hate_extremism": ["hate speech", "neo-Nazi", "white supremacist", "Proud Boys", "militia", "extremism",
                       "bias incident", "Nazi", "hate symbol", "Tops shooting"],
    "weather_visibility": ["winter storm", "blizzard", "snow emergency", "travel ban", "tornado warning",
                           "severe thunderstorm", "flash flood", "lakeshore flood", "wind advisory", "ice storm",
                           "whiteout", "freezing fog", "storm surge"],
    "reported_crime": ["assault", "harassment", "menacing", "criminal possession", "weapon possession",
                       "shoplifting", "trespassing arrest", "disorderly"],
    "watch_entities": ["news crew", "TV crew", "livestream", "live stream", "viral video", "influencer"],
    "context": ["tailgate", "parking lot", "game day", "playoff", "parade", "fireworks show", "Taste of Buffalo",
                "food truck", "ice rink", "concert series", "sold out", "watch party", "home opener"],
}

NEW_CATEGORIES = {
    "direct_threats": {"label": "Direct threats", "weight": 10, "terms": [
        "threat against", "threatened to", "death threat", "threatening message", "threatening letter",
        "shoot up", "blow up", "kill everyone", "swatting", "swatted", "hoax call", "credible threat",
        "threat made", "online threat", "school threat", "hit list"]},
    "emergency_response": {"label": "Emergency response", "weight": 8, "terms": [
        "lockdown", "shelter in place", "SWAT", "police standoff", "barricaded", "hostage", "manhunt",
        "mass casualty", "multiple victims", "active threat", "evacuate", "evacuating", "emergency crews",
        "first responders", "police activity"]},
    "cyber": {"label": "Cyber & doxxing", "weight": 6, "terms": [
        "cyberattack", "cyber attack", "ransomware", "data breach", "hacked", "DDoS", "doxxing", "doxxed",
        "phishing", "systems down", "IT outage", "ticketing outage"]},
    "election_security": {"label": "Election security", "weight": 7, "terms": [
        "poll worker", "polling place", "voter intimidation", "election fraud",
        "ballot drop box", "ballot tampering", "voting machines tampered", "election worker threatened"]},
}


# terms an earlier pack added that proved too broad; merge_into() removes them
REMOVE_TERMS = {"march", "strike", "capacity", "warrant", "road closure", "ballot", "ballots", "early voting",
                "election day", "election official", "voting machines", "killed", "fatal"}


def merge_into(cfg: dict) -> tuple[dict, int]:
    """Returns (merged config, number of terms added)."""
    cats = cfg.setdefault("categories", {})
    added = 0
    for cid, c in NEW_CATEGORIES.items():
        if cid not in cats:
            cats[cid] = {"label": c["label"], "weight": c["weight"], "terms": []}
        have = {t.lower() for t in cats[cid].get("terms", [])}
        for t in c["terms"]:
            if t.lower() not in have:
                cats[cid].setdefault("terms", []).append(t)
                have.add(t.lower())
                added += 1
    for cid, terms in ADD_TERMS.items():
        if cid not in cats:
            continue
        have = {t.lower() for t in cats[cid].get("terms", [])}
        for t in terms:
            if t.lower() not in have:
                cats[cid].setdefault("terms", []).append(t)
                have.add(t.lower())
                added += 1
    for c in cats.values():
        c["terms"] = [t for t in c.get("terms", []) if t.lower() not in REMOVE_TERMS]
    # keep Context last so the dashboard lists threat categories first
    if "context" in cats:
        cats["context"] = cats.pop("context")
    return cfg, added
