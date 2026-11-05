import io, json, os, ssl, sys, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
ctx = ssl.create_default_context()
h = {"Authorization": f"token {os.environ.get('GH_TOKEN', '')}", "User-Agent": "check-agent"}
for i in [12, 13, 14, 15, 16]:
    req = urllib.request.Request(f"https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/{i}", headers=h)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as response: data = json.loads(response.read())
    print(f"=== Issue #{i} ===\nTitle: {data['title']}\nBody: {data.get('body', '')[:300]}\n")
