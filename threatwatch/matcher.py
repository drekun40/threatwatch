"""Facility + threat keyword matching."""
from __future__ import annotations

import re

from .geo import facilities_near
from .models import Match, Post

AREA_GENERAL = "area_general"   # pseudo-facility: Buffalo-area threat not tied to a listed site


def term_pattern(term: str) -> str:
    """Regex for a keyword: case-insensitive, word-bounded, flexible whitespace, simple plurals."""
    t = term.strip()
    body = re.escape(t).replace(r"\ ", r"\s+")
    if t and t[-1].isalpha() and len(t) > 2:
        body += r"(?:s|es)?"
    return rf"(?<![\w#]){body}(?!\w)" if not t.startswith("#") else rf"(?<!\w){body}(?!\w)"


def compile_terms(terms: list[str], ignore_case: bool = True) -> re.Pattern | None:
    terms = [t for t in terms if t and t.strip()]
    if not terms:
        return None
    # longest first so "active shooter" wins over "shooter" in the reported term
    terms = sorted(set(terms), key=len, reverse=True)
    return re.compile("|".join(f"({term_pattern(t)})" for t in terms), re.IGNORECASE if ignore_case else 0)


class Matcher:
    def __init__(self, facilities_cfg: dict, keywords_cfg: dict, filters_cfg: dict | None = None):
        if filters_cfg is None:
            from .config import load_filters
            filters_cfg = load_filters()
        self.not_buffalo_re = compile_terms(filters_cfg.get("not_buffalo", []))
        damp = filters_cfg.get("dampeners", {}) or {}
        self.dampener_re = compile_terms(damp.get("terms", []))
        self.dampener_penalty = int(damp.get("penalty", 15))
        self.facilities = {f["id"]: f for f in facilities_cfg.get("facilities", [])}
        self.context_re = compile_terms(facilities_cfg.get("context_terms", []))

        self.fac_direct: dict[str, re.Pattern] = {}
        self.fac_ambiguous: dict[str, re.Pattern] = {}
        self.fac_nearby: dict[str, re.Pattern] = {}
        for fid, f in self.facilities.items():
            names = [] if f.get("match_name") is False else [f["name"].split(" (")[0].split(" —")[0]]
            p = compile_terms(f.get("aliases", []) + names)
            if p:
                self.fac_direct[fid] = p
            pa = compile_terms(f.get("ambiguous", []))
            if pa:
                self.fac_ambiguous[fid] = pa
            # nearby streets/intersections: case-sensitive, so "Best Street" isn't "the best street food"
            pn = compile_terms(f.get("nearby", []), ignore_case=False)
            if pn:
                self.fac_nearby[fid] = pn

        self.categories = keywords_cfg.get("categories", {})
        self.cat_re: dict[str, re.Pattern] = {}
        for cat, c in self.categories.items():
            p = compile_terms(c.get("terms", []))
            if p:
                self.cat_re[cat] = p

    def weight(self, cat: str) -> int:
        return int(self.categories.get(cat, {}).get("weight", 0))

    def label(self, cat: str) -> str:
        return self.categories.get(cat, {}).get("label", cat)

    def facility_name(self, fid: str) -> str:
        if fid == AREA_GENERAL:
            return "Buffalo area (no specific facility)"
        return self.facilities.get(fid, {}).get("name", fid)

    def match(self, post: Post) -> Match:
        # headline/summary plus the article's lead paragraphs when they were fetched
        text = "\n".join(t for t in (post.text, getattr(post, "body", "")) if t)
        # "water buffalo", "News 4 Buffalo" etc. don't put a story in Buffalo
        place_text = self.not_buffalo_re.sub(" ", text) if self.not_buffalo_re else text
        mentions_area = bool(self.context_re and self.context_re.search(place_text))
        # local outlets also carry national wire stories, so being local only helps resolve
        # ambiguous site aliases; an area-wide item needs the text itself to name the area
        in_buffalo = post.is_local or mentions_area

        facilities = [fid for fid, p in self.fac_direct.items() if p.search(text)]
        if post.lat is not None and post.lon is not None:   # located items: nearest geofence only,
            near = facilities_near(post.lat, post.lon, self.facilities)   # so overlapping downtown
            if near and near[0][0] not in facilities:                     # fences don't duplicate hits
                facilities.append(near[0][0])
            in_buffalo = mentions_area = True
        if in_buffalo:
            facilities += [fid for fid, p in self.fac_ambiguous.items()
                           if fid not in facilities and p.search(text)]
        proximity: dict[str, str] = {}   # site -> the street/intersection that placed the story there
        if in_buffalo:
            for fid, p in self.fac_nearby.items():
                m = p.search(text) if fid not in facilities else None
                if m:
                    proximity[fid] = " ".join(m.group(0).split())
                    facilities.append(fid)

        threat: dict[str, list[str]] = {}
        context: list[str] = []
        for cat, p in self.cat_re.items():
            found = sorted({m.group(0).strip() for m in p.finditer(text)}, key=str.lower)
            if not found:
                continue
            if self.weight(cat) > 0:
                threat[cat] = found
            else:
                context.extend(found)

        area_only = False
        if not facilities and threat and mentions_area:
            facilities = [AREA_GENERAL]
            area_only = True

        damp = sorted({m.group(0).strip() for m in self.dampener_re.finditer(text)}, key=str.lower) \
            if self.dampener_re else []
        body_sites, body_cats = [], []
        if getattr(post, "body", ""):   # what the headline alone supports (scoring caps body-only evidence)
            head = post.text or ""
            head_sites = {fid for fid, p in self.fac_direct.items() if p.search(head)}
            if in_buffalo:
                head_sites |= {fid for fid, p in {**self.fac_ambiguous, **self.fac_nearby}.items() if p.search(head)}
            if post.lat is not None and post.lon is not None:
                head_sites |= set(facilities)
            body_sites = [f for f in facilities if f != AREA_GENERAL and f not in head_sites]
            body_cats = [c for c in threat if not self.cat_re[c].search(head)]
        return Match(facilities=facilities, threat_terms=threat,
                     context_terms=context, area_only=area_only, dampeners=damp, proximity=proximity,
                     body_sites=body_sites, body_categories=body_cats)
