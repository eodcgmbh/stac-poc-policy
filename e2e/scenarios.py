import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROXY = "http://127.0.0.1:18000"


def compose_python(service, code, *args):
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", service, "python", "-c", code, *args],
        capture_output=True, text=True, check=True, cwd=HERE,
    )
    return out.stdout.strip()


def token(claims):
    query = urllib.parse.urlencode({"claims": json.dumps(claims)})
    code = f"import urllib.request; print(urllib.request.urlopen('http://oidc:8000/token?{query}').read().decode())"
    return json.loads(compose_python("proxy", code))["access_token"]


def upstream_post(path, body):
    code = (
        "import sys, urllib.request\n"
        "r = urllib.request.Request('http://localhost:8080' + sys.argv[1], method='POST', data=sys.argv[2].encode(), headers={'Content-Type': 'application/json'})\n"
        "print(urllib.request.urlopen(r).status)"
    )
    return compose_python("stac", code, path, json.dumps(body))


def call(method, path, tok=None, body=None):
    headers = {"Content-Type": "application/json"}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(PROXY + path, method=method, headers=headers, data=data)
    start = time.time()
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, json.loads(response.read() or b"null"), time.time() - start
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200], time.time() - start


def collection(cid, access):
    c = {
        "type": "Collection", "stac_version": "1.0.0", "id": cid, "description": cid, "license": "CC-BY-4.0", "links": [],
        "extent": {"spatial": {"bbox": [[9, 46, 17, 49]]}, "temporal": {"interval": [["2012-01-01T00:00:00Z", None]]}},
    }
    if access is not None:
        c["access"] = access
    return c


def item(cid, i):
    return {
        "type": "Feature", "stac_version": "1.0.0", "id": f"{cid}-{i:04d}", "collection": cid,
        "geometry": {"type": "Polygon", "coordinates": [[[9, 46], [17, 46], [17, 49], [9, 49], [9, 46]]]},
        "bbox": [9, 46, 17, 49], "properties": {"datetime": f"2012-01-01T{i % 24:02d}:00:00Z"}, "links": [],
        "assets": {"data": {"href": f"https://example.com/{i}.nc", "type": "application/netcdf"}},
    }


def ids(response):
    status, body, _ = response
    return sorted(c["id"] for c in body["collections"]) if status == 200 else (status, body)


def feature_count(response):
    status, body, _ = response
    return len(body["features"]) if status == 200 else (status, body)


results = []


def check(name, got, *allowed):
    ok = got in allowed
    results.append(ok)
    print("OK  " if ok else "FAIL", f"{name}: {got}")


owner = token({"email": "owner@geosphere.at", "email_verified": True})
other = token({"email": "someone@eodc.eu", "email_verified": True, "organisation": "eodc"})
member = token({"email": "a@tuwien.ac.at", "email_verified": True})
spoofed = token({"preferred_username": "owner@geosphere.at"})
unverified = token({"email": "owner@geosphere.at", "email_verified": False})

PUBLIC = {"visibility": "public", "allowed_users": [], "allowed_organisations": [], "allowed_domains": ["geosphere.at"]}
RESTRICTED = {"visibility": "user", "allowed_users": ["a@tuwien.ac.at"], "allowed_organisations": []}
UNOWNED = {"visibility": "public", "allowed_users": [], "allowed_organisations": []}

upstream_post("/collections", collection("no-access", None))
upstream_post("/collections", collection("unowned", UNOWNED))

check("anonymous POST /collections", call("POST", "/collections", None, collection("x", PUBLIC))[0], 401)
check("owner creates public collection", call("POST", "/collections", owner, collection("public", PUBLIC))[0], 200, 201)
check("member creates restricted collection", call("POST", "/collections", member, collection("restricted", RESTRICTED))[0], 200, 201)
check("public collection without owner is rejected", call("POST", "/collections", owner, collection("no-owner", UNOWNED))[0], 403)
check("spoofed username cannot create owned collection", call("POST", "/collections", spoofed, collection("spoof", PUBLIC))[0], 403)
check("unverified email cannot create owned collection", call("POST", "/collections", unverified, collection("unverified", PUBLIC))[0], 403)

bulk = {"items": {f"public-{i:04d}": item("public", i) for i in range(100)}, "method": "insert"}
status, _, seconds = call("POST", "/collections/public/bulk_items", owner, bulk)
check(f"owner bulk-inserts 100 items ({seconds:.1f}s)", status, 200)
check("other user cannot bulk-insert", call("POST", "/collections/public/bulk_items", other, {"items": {"public-x": item("public", 9999)}, "method": "insert"})[0], 403)
check("other user cannot POST item", call("POST", "/collections/public/items", other, item("public", 9998))[0], 403)
check("anonymous cannot POST item", call("POST", "/collections/public/items", None, item("public", 9997))[0], 401)
check("member posts item into restricted collection", call("POST", "/collections/restricted/items", member, item("restricted", 1))[0], 200, 201)
check("owner cannot post into restricted collection", call("POST", "/collections/restricted/items", owner, item("restricted", 2))[0], 403, 404)

check("anonymous sees only public collections", ids(call("GET", "/collections")), ["public", "unowned"])
check("member additionally sees restricted collection", ids(call("GET", "/collections", member)), ["public", "restricted", "unowned"])
check("anonymous GET restricted collection", call("GET", "/collections/restricted")[0], 404)
check("anonymous gets no restricted items", feature_count(call("GET", "/collections/restricted/items")), 0, (404, ""))
check("anonymous GET single restricted item", call("GET", "/collections/restricted/items/restricted-0001")[0], 404)
check("member GET single restricted item", call("GET", "/collections/restricted/items/restricted-0001", member)[0], 200)
status, body, _ = call("GET", "/search?limit=200")
check("anonymous search returns only public items", sorted({f["collection"] for f in body["features"]}) if status == 200 else (status, body), ["public"])
check("anonymous POST search for restricted returns nothing", feature_count(call("POST", "/search", None, {"limit": 200, "collections": ["restricted"]})), 0)
check("member POST search for restricted returns its item", feature_count(call("POST", "/search", member, {"limit": 200, "collections": ["restricted"]})), 1)
check("anonymous reads public items", feature_count(call("GET", "/collections/public/items?limit=200")), 100)

updated = collection("public", PUBLIC)
updated["title"] = "updated"
takeover = collection("public", {**PUBLIC, "allowed_domains": ["eodc.eu"]})
check("other user cannot PUT public collection", call("PUT", "/collections/public", other, updated)[0], 403, 404)
check("owner PUTs public collection", call("PUT", "/collections/public", owner, updated)[0], 200)
check("other user cannot take over ownership", call("PUT", "/collections/public", other, takeover)[0], 403, 404)
check("owner cannot fix a collection without owner entry", call("PUT", "/collections/unowned", owner, collection("unowned", PUBLIC))[0], 403, 404)
check("other user cannot DELETE public item", call("DELETE", "/collections/public/items/public-0001", other)[0], 403, 404)
check("owner DELETEs public item", call("DELETE", "/collections/public/items/public-0001", owner)[0], 200, 204)
check("other user cannot DELETE restricted collection", call("DELETE", "/collections/restricted", other)[0], 403, 404)
check("member DELETEs restricted collection", call("DELETE", "/collections/restricted", member)[0], 200, 204)

group_member = token({"email": "g@example.org", "email_verified": True, "groups": ["/services/data-access/bfw"]})
outsider = token({"email": "o@example.org", "email_verified": True, "groups": ["/openstack_projects/bfw", "/services/data-access/__data-access-admin__"]})
GROUP = {"visibility": "group", "allowed_groups": ["bfw"]}
GROUP_OWNED = {"visibility": "public", "allowed_groups": ["bfw"]}

check("group member creates group collection", call("POST", "/collections", group_member, collection("grp", GROUP))[0], 200, 201)
check("group member creates public group-owned collection", call("POST", "/collections", group_member, collection("grp-owned", GROUP_OWNED))[0], 200, 201)
check("outsider cannot create group-owned collection", call("POST", "/collections", outsider, collection("grp-x", GROUP_OWNED))[0], 403)
check("anonymous does not see group collection", ids(call("GET", "/collections")), ["grp-owned", "public", "unowned"])
check("group member sees group collection", ids(call("GET", "/collections", group_member)), ["grp", "grp-owned", "public", "unowned"])
check("outsider with other groups does not see it", call("GET", "/collections/grp", outsider)[0], 404)
check("group member bulk-inserts into group collection", call("POST", "/collections/grp/bulk_items", group_member, {"items": {"grp-0001": item("grp", 1)}, "method": "insert"})[0], 200)
check("outsider cannot insert into group collection", call("POST", "/collections/grp/items", outsider, item("grp", 2))[0], 403, 404)
time.sleep(6)
check("anonymous gets no group items via search", feature_count(call("POST", "/search", None, {"limit": 200, "collections": ["grp"]})), 0)
check("group member finds group items via search", feature_count(call("POST", "/search", group_member, {"limit": 200, "collections": ["grp"]})), 1)
check("group member updates group-owned public collection", call("PUT", "/collections/grp-owned", group_member, collection("grp-owned", GROUP_OWNED))[0], 200)
check("outsider cannot update group-owned public collection", call("PUT", "/collections/grp-owned", outsider, collection("grp-owned", GROUP_OWNED))[0], 403, 404)
check("group member deletes group collection", call("DELETE", "/collections/grp", group_member)[0], 200, 204)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
