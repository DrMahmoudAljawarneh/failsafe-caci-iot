"""Fetch OpenAlex abstracts for the DOIs used in the synthesis matrix.

Reproducibility helper, not part of the paper build. OpenAlex stores abstracts as
an inverted index; reconstruct the text and cache it in literature/abstracts.json.
"""

import json
import re
import sys
import urllib.request

DOIS = [
    "10.1109/jiot.2024.3371504",
    "10.1109/jiot.2025.3579028",
    "10.1016/j.jksuci.2020.11.023",
    "10.1109/siot.2017.00010",
    "10.5220/0006292602540260",
    "10.1109/isncc.2019.8909196",
    "10.1109/icc.2019.8761830",
    "10.1007/s10922-025-10003-8",
    "10.1109/access.2019.2927037",
    "10.1007/978-3-642-02161-9_1",
    "10.23919/fmcad.2019.8894264",
    "10.1145/3061639.3072957",
    "10.1145/3558482.3590188",
    "10.1109/jiot.2020.2969326",
    "10.1016/j.jnca.2019.06.017",
    "10.3390/electronics12030566",
    "10.1016/j.adhoc.2024.103414",
    "10.1109/ACCESS.2022.3165809",
    "10.3390/s23135941",
    "10.1109/iaw.2005.1495974",
    "10.1109/tvt.2008.921621",
    "10.1109/tcyb.2019.2915124",
    "10.1109/ms.2001.936213",
    "10.1007/978-3-031-06773-0_12",
    "10.1007/s00145-021-09398-9",
    "10.1109/access.2025.3529757",
    "10.1109/trustcom50675.2020.00100",
    "10.1016/j.scs.2021.102994",
    "10.1145/984334.984339",
    "10.6028/NIST.SP.800-207",
]


def reconstruct(inverted):
    if not inverted:
        return ""
    positions = []
    for word, idxs in inverted.items():
        for i in idxs:
            positions.append((i, word))
    return " ".join(w for _, w in sorted(positions))


def fetch(doi):
    url = "https://api.openalex.org/works/https://doi.org/" + doi
    req = urllib.request.Request(url, headers={"User-Agent": "scholar-agent/1.0 (mailto:ma_jawarneh@asu.edu.jo)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    return {
        "doi": doi,
        "title": data.get("title"),
        "year": data.get("publication_year"),
        "venue": ((data.get("primary_location") or {}).get("source") or {}).get("display_name"),
        "abstract": re.sub(r"\s+", " ", reconstruct(data.get("abstract_inverted_index"))).strip(),
        "cited_by": data.get("cited_by_count"),
    }


if __name__ == "__main__":
    out = {}
    for doi in DOIS:
        try:
            rec = fetch(doi)
            out[doi] = rec
            print(("OK  " if rec["abstract"] else "NOABS ") + doi + "  " + (rec["title"] or "")[:70])
        except Exception as exc:  # noqa: BLE001
            print("FAIL", doi, exc, file=sys.stderr)
    with open("literature/abstracts.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
