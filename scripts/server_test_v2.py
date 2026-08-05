#!/usr/bin/env python3
import json,pathlib,socket,subprocess,tempfile,time,urllib.parse,statistics
from concurrent.futures import ThreadPoolExecutor,as_completed
SRC=pathlib.Path("/tmp/v2-candidates.txt"); OUT=pathlib.Path("/tmp/v2-tested.txt"); URL="http://www.gstatic.com/generate_204"
nodes=list(dict.fromkeys(x.strip() for x in SRC.read_text().splitlines() if x.strip().startswith("trojan://")))
def port():
 s=socket.socket();s.bind(("127.0.0.1",0));p=s.getsockname()[1];s.close();return p
def test(node):
 u=urllib.parse.urlsplit(node)
 if not u.hostname or not u.port or not u.username:return None
 p=port(); cfg={"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":p,"protocol":"socks","settings":{"udp":False}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":u.hostname,"port":u.port,"password":urllib.parse.unquote(u.username)}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":u.hostname,"allowInsecure":False}}}]}
 with tempfile.TemporaryDirectory() as d:
  f=pathlib.Path(d)/"c.json";f.write_text(json.dumps(cfg));q=subprocess.Popen(["xray","run","-config",str(f)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   time.sleep(.7);ds=[]
   for _ in range(3):
    t=time.monotonic();r=subprocess.run(["curl","-sS","--max-time","8","--connect-timeout","5","--socks5-hostname",f"127.0.0.1:{p}","-o","/dev/null","-w","%{http_code}",URL],capture_output=True,text=True,timeout=10)
    if r.returncode or r.stdout.strip()!="204":return None
    ds.append((time.monotonic()-t)*1000)
   return statistics.median(ds),node
  except Exception:return None
  finally:
   q.terminate()
   try:q.wait(timeout=2)
   except subprocess.TimeoutExpired:q.kill()
print("testing",len(nodes),"nodes")
passed=[]
with ThreadPoolExecutor(max_workers=6) as ex:
 for f in as_completed([ex.submit(test,n) for n in nodes]):
  r=f.result()
  if r:passed.append(r);print("PASS",round(r[0]),"ms")
passed.sort()
OUT.write_text("\n".join(n.split("#",1)[0]+f"#%E6%96%B0%E5%8A%A0%E5%9D%A1%20{i}" for i,(_,n) in enumerate(passed,1))+"\n")
print("passed",len(passed),"of",len(nodes),"saved",OUT)
