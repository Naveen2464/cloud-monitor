import json, urllib.request, time

ES  = "http://localhost:9200"
KIB = "http://localhost:5601"

def kib_post(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(f"{KIB}{path}", data=data,
        headers={"Content-Type":"application/json","kbn-xsrf":"true"}, method="POST")
    try:
        res = urllib.request.urlopen(req, timeout=10)
        return json.loads(res.read())
    except Exception as e:
        print(f"  WARN: {e}")
        return {}

def wait_for_kibana():
    print("Waiting for Kibana...")
    for _ in range(30):
        try:
            res  = urllib.request.urlopen(f"{KIB}/api/status", timeout=5)
            data = json.loads(res.read())
            if data.get("status",{}).get("overall",{}).get("level") == "available":
                print("  Kibana ready!")
                return True
        except: pass
        print("  ..waiting 5s")
        time.sleep(5)
    return False

def create_index_patterns():
    print("\nCreating index patterns...")
    for title in ["cloud-monitor-*","login-events-*","security-alerts-*","sessions-*"]:
        r = kib_post("/api/saved_objects/index-pattern",
            {"attributes":{"title":title,"timeFieldName":"@timestamp"}})
        print(f"  {'OK' if r.get('id') else 'WARN'} {title}")

def check_indices():
    print("\nElasticsearch indices:")
    try:
        res  = urllib.request.urlopen(f"{ES}/_cat/indices?format=json", timeout=5)
        data = json.loads(res.read())
        for idx in data:
            print(f"  {idx.get('index')} — {idx.get('docs.count','0')} docs")
    except Exception as e:
        print(f"  No indices yet: {e}")

if __name__ == "__main__":
    print("="*50)
    print("  Cloud Monitor — Kibana Setup")
    print("="*50)
    if wait_for_kibana():
        create_index_patterns()
        check_indices()
        print("\nDone! Open: http://localhost:5601")
        print("Go to: Discover → cloud-monitor-* → see live events")
    else:
        print("Kibana not ready. Run: cd elk && docker-compose up -d")