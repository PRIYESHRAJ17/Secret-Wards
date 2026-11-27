"""Cross-document, cross-script patient identity linkage with hard vetoes & k-anonymity stats."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from src.textnorm import canonical_name_parts, normalize_match, norm_mrn


@dataclass
class RecordProfile:
    file_rel: str
    loc: str
    hospital: str = ""
    aadhaar: str = ""
    abha: str = ""
    pan: str = ""
    email: str = ""
    mrn: str = ""
    sex: str = ""
    birth_year: int | None = None
    extra_strong_ids: list[str] = field(default_factory=list)
    # Phase 3-5 rich linking & privacy signals
    phone: str = ""
    full_name: str = ""
    relative_name: str = ""
    village: str = ""
    district: str = ""
    pin: str = ""
    age: int | None = None
    birth_year_is_exact: bool = True
    conditions: list[str] = field(default_factory=list)
    is_patient_record: bool = True


def _canon_hospital(hosp: str, file_rel: str = "", mrn: str = "") -> str:
    low = normalize_match(f"{hosp} {file_rel} {mrn}")
    if "sanjeevani" in low or "snj" in low:
        return "sanjeevani"
    if "jeevan" in low or "jyoti" in low or "jjh" in low:
        return "jeevanjyoti"
    if "arogya" in low or "uhid" in low:
        return "arogya"
    if "hardoi" in low or "dhh" in low:
        return "dhh"
    return normalize_match(hosp)


def _norm_sex(s: str) -> str:
    low = normalize_match(s)
    if not low:
        return ""
    if low in ("f", "female", "mahila", "महिला", "woman", "girl") or low.startswith("f"):
        return "F"
    if low in ("m", "male", "purush", "पुरुष", "man", "boy") or low.startswith("m"):
        return "M"
    return ""


def _mrn_tokens(mrn_raw: str, hosp_canon: str) -> tuple[list[str], str]:
    """Return (link_keys, hospital_global_id) splitting prefixed vs local admission IDs."""
    if not mrn_raw:
        return [], ""
    keys: list[str] = []
    global_id = ""
    canon, scope = norm_mrn(mrn_raw)
    if not canon:
        return [], ""
    if scope == "global":
        keys.append(f"gmrn:{canon}")
        global_id = canon
    elif hosp_canon:
        keys.append(f"lmrn:{hosp_canon}:{canon}")
    else:
        keys.append(f"lmrn::{canon}")
    return keys, global_id


def _skel_tokens_match(sk_a: str, sk_b: str) -> bool:
    if not sk_a or not sk_b:
        return False
    ta, tb = sk_a.split(), sk_b.split()
    if len(ta) >= 2 and len(tb) >= 2:
        if ta == tb or (ta[0] == tb[0] and ta[-1] == tb[-1]):
            return True
        # Minor spelling/edit tolerance when consonant skeletons share first+last prefix
        if len(ta[0]) >= 2 and len(tb[0]) >= 2 and (ta[0].startswith(tb[0][:2]) or tb[0].startswith(ta[0][:2])):
            if ta[-1] == tb[-1] or (len(ta[-1]) >= 2 and len(tb[-1]) >= 2 and ta[-1][:2] == tb[-1][:2]):
                return True
    return False


def _token_overlap(ta: list[str], tb: list[str]) -> bool:
    if not ta or not tb:
        return False
    return bool(set(ta) & set(tb)) or ta[0] == tb[0]


def _profile_compat(a: RecordProfile, b: RecordProfile, exact_names: bool = False) -> bool:
    if a.aadhaar and b.aadhaar and a.aadhaar != b.aadhaar:
        return False
    if a.abha and b.abha and a.abha != b.abha:
        return False
    if a.email and b.email and normalize_match(a.email) != normalize_match(b.email):
        return False
    sa, sb = _norm_sex(a.sex), _norm_sex(b.sex)
    if sa and sb and sa != sb:
        return False
    if a.birth_year is not None and b.birth_year is not None:
        tol = 3 if (a.birth_year_is_exact and b.birth_year_is_exact) else 5
        if abs(a.birth_year - b.birth_year) > tol:
            return False
    if exact_names and a.full_name and b.full_name:
        _, _, ska = canonical_name_parts(a.full_name)
        _, _, skb = canonical_name_parts(b.full_name)
        if ska and skb and not _token_overlap(ska.split(), skb.split()):
            return False
    return True


def build_clusters(
    profiles: list[RecordProfile],
    cfg: dict | None = None,
) -> tuple[dict[tuple[str, str], str], dict[str, dict]]:
    """Link records across formats/scripts with hard vetoes and compute privacy risk metadata.

    Returns:
      - anchor_map: {(file_rel, loc): canonical_cluster_anchor}
      - cluster_privacy: {canonical_cluster_anchor: {age_band_width, pin_prefix_digits, coarsen_dob_width, suppress_district, k_group}}
    """
    n = len(profiles)
    if n == 0:
        return {}, {}

    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            if rx < ry:
                parent[ry] = rx
            else:
                parent[rx] = ry

    # Stage 1: Exact strong ID indexing (with hard vetoes & phone compatibility guard)
    by_id: dict[str, list[int]] = defaultdict(list)
    by_phone: dict[str, list[int]] = defaultdict(list)
    hosp_list = [_canon_hospital(p.hospital, p.file_rel, p.mrn) for p in profiles]

    for idx, p in enumerate(profiles):
        if p.aadhaar:
            by_id[f"aadhaar:{p.aadhaar}"].append(idx)
        if p.abha:
            by_id[f"abha:{p.abha}"].append(idx)
        if p.pan:
            by_id[f"pan:{normalize_match(p.pan).upper()}"].append(idx)
        if p.email:
            by_id[f"email:{normalize_match(p.email)}"].append(idx)
        for mval in [p.mrn, *p.extra_strong_ids]:
            keys, _ = _mrn_tokens(mval, hosp_list[idx])
            for k in keys:
                by_id[k].append(idx)
        if p.phone:
            by_phone[p.phone].append(idx)

    for idxs in by_id.values():
        if len(idxs) > 1:
            base = idxs[0]
            for other in idxs[1:]:
                if _profile_compat(profiles[base], profiles[other], exact_names=False):
                    union(base, other)

    for idxs in by_phone.values():
        if len(idxs) > 1:
            for i in range(len(idxs)):
                for j in range(i + 1, len(idxs)):
                    if _profile_compat(profiles[idxs[i]], profiles[idxs[j]], exact_names=True):
                        union(idxs[i], idxs[j])

    # Build per-component aggregated descriptors for Stage 2 cross-script merging
    def _comp_summary(indices: list[int]) -> dict:
        full_sks: set[str] = set()
        given_sks: set[str] = set()
        rel_sks: set[str] = set()
        vil_sks: set[str] = set()
        sexes: set[str] = set()
        aadhaars: set[str] = set()
        abhas: set[str] = set()
        emails: set[str] = set()
        gmrns_by_hosp: dict[str, set[str]] = defaultdict(set)
        by_exact: list[int] = []
        by_approx: list[int] = []
        pins: set[str] = set()
        districts: set[str] = set()
        phones: set[str] = set()

        for idx in indices:
            pr = profiles[idx]
            hc = hosp_list[idx]
            if pr.aadhaar:
                aadhaars.add(pr.aadhaar)
            if pr.abha:
                abhas.add(pr.abha)
            if pr.email:
                emails.add(normalize_match(pr.email))
            if pr.phone:
                phones.add(pr.phone)
            for mval in [pr.mrn, *pr.extra_strong_ids]:
                _, gmrn = _mrn_tokens(mval, hc)
                if gmrn:
                    pfx = gmrn[:3]
                    gmrns_by_hosp[pfx].add(gmrn)
            sx = _norm_sex(pr.sex)
            if sx:
                sexes.add(sx)
            if pr.birth_year is not None:
                (by_exact if pr.birth_year_is_exact else by_approx).append(pr.birth_year)
            if pr.full_name:
                _, toks, sk = canonical_name_parts(pr.full_name)
                if len(sk.split()) >= 2:
                    full_sks.add(sk)
                if toks:
                    first_sk = sk.split()[0] if sk.split() else ""
                    if first_sk:
                        given_sks.add(first_sk)
            if pr.relative_name:
                _, _, rsk = canonical_name_parts(pr.relative_name)
                if rsk:
                    rel_sks.add(rsk)
            if pr.village:
                _, _, vsk = canonical_name_parts(pr.village)
                if vsk:
                    vil_sks.add(vsk)
            if pr.pin and len(pr.pin) == 6:
                pins.add(pr.pin)
            if pr.district:
                districts.add(normalize_match(pr.district))

        all_by = by_exact or by_approx
        return {
            "indices": indices,
            "full_sks": full_sks,
            "given_sks": given_sks,
            "rel_sks": rel_sks,
            "vil_sks": vil_sks,
            "sexes": sexes,
            "aadhaars": aadhaars,
            "abhas": abhas,
            "emails": emails,
            "gmrns_by_hosp": gmrns_by_hosp,
            "by_min": min(all_by) if all_by else None,
            "by_max": max(all_by) if all_by else None,
            "by_exact": bool(by_exact),
            "pins": pins,
            "districts": districts,
            "phones": phones,
        }

    # Index components and first-name+relative uniqueness counts (prevents homonym collisions!)
    comps_map: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        comps_map[find(i)].append(i)
    comp_ids = sorted(comps_map)
    summaries = {cid: _comp_summary(comps_map[cid]) for cid in comp_ids}

    given_rel_freq: Counter[tuple[str, str]] = Counter()
    for cid in comp_ids:
        sm = summaries[cid]
        for gs in sm["given_sks"]:
            for rs in sm["rel_sks"]:
                rfirst = rs.split()[0] if rs.split() else ""
                if gs and rfirst:
                    given_rel_freq[(gs, rfirst)] += 1

    # Iterative greedy cross-script/soft merge with strict vetoes
    merged_roots = {cid: cid for cid in comp_ids}
    pair_candidates: list[tuple[float, int, int]] = []

    def _hard_veto(s1: dict, s2: dict) -> bool:
        if s1["aadhaars"] and s2["aadhaars"] and s1["aadhaars"].isdisjoint(s2["aadhaars"]):
            return True
        if s1["abhas"] and s2["abhas"] and s1["abhas"].isdisjoint(s2["abhas"]):
            return True
        if s1["emails"] and s2["emails"] and s1["emails"].isdisjoint(s2["emails"]):
            return True
        if s1["sexes"] and s2["sexes"] and s1["sexes"].isdisjoint(s2["sexes"]):
            return True
        for pfx in s1["gmrns_by_hosp"].keys() & s2["gmrns_by_hosp"].keys():
            if s1["gmrns_by_hosp"][pfx].isdisjoint(s2["gmrns_by_hosp"][pfx]):
                return True
        if s1["by_min"] is not None and s2["by_min"] is not None:
            tol = 3 if (s1["by_exact"] and s2["by_exact"]) else 5
            if s1["by_min"] > s2["by_max"] + tol or s2["by_min"] > s1["by_max"] + tol:
                return True
        if s1["pins"] and s2["pins"] and s1["pins"].isdisjoint(s2["pins"]):
            return True
        if s1["districts"] and s2["districts"] and s1["districts"].isdisjoint(s2["districts"]):
            return True
        if s1["vil_sks"] and s2["vil_sks"]:
            if not any(v1 == v2 or v1.split()[0] == v2.split()[0] for v1 in s1["vil_sks"] for v2 in s2["vil_sks"]):
                return True
        # Relative veto: if both list relatives and zero token overlap
        if s1["rel_sks"] and s2["rel_sks"]:
            r_match = any(
                _token_overlap(r1.split(), r2.split())
                for r1 in s1["rel_sks"]
                for r2 in s2["rel_sks"]
            )
            if not r_match:
                return True
        return False

    for i_idx in range(len(comp_ids)):
        c1 = comp_ids[i_idx]
        s1 = summaries[c1]
        if not (s1["full_sks"] or s1["given_sks"]):
            continue
        for j_idx in range(i_idx + 1, len(comp_ids)):
            c2 = comp_ids[j_idx]
            s2 = summaries[c2]
            if not (s2["full_sks"] or s2["given_sks"]):
                continue
            if _hard_veto(s1, s2):
                continue

            score = 0.0
            full_hit = any(_skel_tokens_match(a, b) for a in s1["full_sks"] for b in s2["full_sks"])
            if full_hit:
                score += 4.5
            else:
                g_hit = bool(s1["given_sks"] & s2["given_sks"])
                if not g_hit:
                    continue
                score += 1.5

            if s1["phones"] & s2["phones"]:
                score += 5.0
            if s1["rel_sks"] and s2["rel_sks"]:
                exact_rel = any(_skel_tokens_match(r1, r2) for r1 in s1["rel_sks"] for r2 in s2["rel_sks"])
                first_rel = any(r1.split()[0] == r2.split()[0] for r1 in s1["rel_sks"] for r2 in s2["rel_sks"] if r1.split() and r2.split())
                if exact_rel:
                    score += 3.5
                elif first_rel:
                    score += 2.5
                if (exact_rel or first_rel) and not full_hit:
                    for gs in sorted(s1["given_sks"] & s2["given_sks"]):
                        rf = next((r.split()[0] for r in sorted(s1["rel_sks"]) if r.split()), "")
                        if rf and given_rel_freq[(gs, rf)] <= 2:
                            score += 2.5
                            break
            elif not full_hit:
                # Single-token given-name note (e.g. 'Senthil sahab'): link only if corpus-unique given name + sex agrees
                bare1 = not s1["full_sks"] and not s1["rel_sks"] and not s1["phones"] and not s1["aadhaars"] and not s1["abhas"]
                bare2 = not s2["full_sks"] and not s2["rel_sks"] and not s2["phones"] and not s2["aadhaars"] and not s2["abhas"]
                if (bare1 and s2["full_sks"]) or (bare2 and s1["full_sks"]):
                    for gs in sorted(s1["given_sks"] & s2["given_sks"]):
                        holders = sum(1 for cid in comp_ids if gs in summaries[cid]["given_sks"] and summaries[cid]["full_sks"])
                        if holders == 1 and not (s1["sexes"] and s2["sexes"] and s1["sexes"].isdisjoint(s2["sexes"])):
                            score += 5.0
                            break
            if s1["vil_sks"] and s2["vil_sks"]:
                if any(v1 == v2 or (v1.split()[0] == v2.split()[0] and len(v1.split()[0]) >= 3) for v1 in s1["vil_sks"] for v2 in s2["vil_sks"]):
                    score += 3.0
            if s1["pins"] & s2["pins"]:
                score += 2.5
            if s1["by_min"] is not None and s2["by_min"] is not None:
                if abs(s1["by_min"] - s2["by_min"]) <= 2:
                    score += 1.5
            if s1["sexes"] & s2["sexes"]:
                score += 0.5

            if score >= 6.5:
                pair_candidates.append((score, c1, c2))

    # Apply highest-scoring merges while re-checking merged-group hard vetoes
    pair_candidates.sort(key=lambda x: (-x[0], x[1], x[2]))
    for _, c1, c2 in pair_candidates:
        r1 = find(c1)
        r2 = find(c2)
        if r1 == r2:
            continue
        cur1 = _comp_summary([i for i in range(n) if find(i) == r1])
        cur2 = _comp_summary([i for i in range(n) if find(i) == r2])
        if not _hard_veto(cur1, cur2):
            union(r1, r2)

    # Canonical anchor per final connected component + cluster-level k-anonymity privacy profile
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)

    anchor_by_root: dict[int, str] = {}
    comp_sigs: dict[str, dict] = {}
    for root, idxs in groups.items():
        tokens: list[str] = []
        comp_sexes: set[str] = set()
        comp_dists: set[str] = set()
        comp_ages: list[int] = []
        comp_dxs: list[str] = []
        for idx in idxs:
            p = profiles[idx]
            hc = hosp_list[idx]
            if p.aadhaar:
                tokens.append(f"aadhaar:{p.aadhaar}")
            if p.abha:
                tokens.append(f"abha:{p.abha}")
            if p.pan:
                tokens.append(f"pan:{normalize_match(p.pan)}")
            if p.email:
                tokens.append(f"email:{normalize_match(p.email)}")
            if p.phone:
                tokens.append(f"phone:{p.phone}")
            if p.mrn:
                keys, _ = _mrn_tokens(p.mrn, hc)
                tokens.extend(keys)
            sx = _norm_sex(p.sex)
            if sx:
                comp_sexes.add(sx)
            if p.district:
                comp_dists.add(normalize_match(p.district))
            if p.age is not None:
                comp_ages.append(p.age)
            elif p.birth_year is not None:
                comp_ages.append(max(0, 2026 - p.birth_year))
            comp_dxs.extend(normalize_match(d) for d in p.conditions if d)

        if tokens:
            anchor = sorted(set(tokens))[0]
        else:
            anchor = sorted(f"rec:{profiles[i].file_rel}#{profiles[i].loc}" for i in idxs)[0]
        anchor_by_root[root] = anchor

        rep_age = comp_ages[0] if comp_ages else -1
        age_cell = (rep_age // 5) * 5 if rep_age >= 0 else -1
        dist_key = sorted(comp_dists)[0] if comp_dists else ""
        sex_key = sorted(comp_sexes)[0] if comp_sexes else ""
        comp_sigs[anchor] = {
            "age": rep_age,
            "age_cell": age_cell,
            "district": dist_key,
            "sex": sex_key,
            "dxs": set(comp_dxs),
        }

    # Global quasi-identifier cell counts & diagnosis frequency across dataset
    qi_counts = Counter(
        (sig["district"], sig["age_cell"], sig["sex"])
        for sig in comp_sigs.values()
        if sig["age_cell"] >= 0
    )
    dx_counts = Counter(dx for sig in comp_sigs.values() for dx in sig["dxs"])
    min_group = int((cfg or {}).get("min_group_size", 5))
    base_age_w = int((cfg or {}).get("age_band_years", 5))
    base_pin_digits = int((cfg or {}).get("pin_prefix_digits", 3))

    cluster_privacy: dict[str, dict] = {}
    for anchor, sig in comp_sigs.items():
        k_cell = qi_counts.get((sig["district"], sig["age_cell"], sig["sex"]), min_group)
        is_elderly = sig["age"] >= 80
        has_rare_dx = any(dx_counts[d] <= 2 for d in sig["dxs"])
        high_risk = is_elderly or has_rare_dx
        cluster_privacy[anchor] = {
            "k_group": k_cell,
            "high_risk": high_risk,
            "age_band_width": 20 if high_risk else (10 if k_cell < 3 else base_age_w),
            "pin_prefix_digits": 0 if high_risk else base_pin_digits,
            "coarsen_dob_width": 10 if high_risk else 5,
            "suppress_district": bool(is_elderly and has_rare_dx),
        }

    anchor_map: dict[tuple[str, str], str] = {}
    for i, p in enumerate(profiles):
        anchor_map[(p.file_rel, p.loc)] = anchor_by_root[find(i)]
    return anchor_map, cluster_privacy


def build_strong_clusters(profiles: list[RecordProfile]) -> dict[tuple[str, str], str]:
    """Backward-compatible wrapper returning {(file_rel, loc): canonical_anchor}."""
    anchor_map, _ = build_clusters(profiles)
    return anchor_map
