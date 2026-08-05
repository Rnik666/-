#!/usr/bin/env python3
import json,pathlib,socket,subprocess,tempfile,time,urllib.parse,statistics
from concurrent.futures import ThreadPoolExecutor,as_completed
SRC=pathlib.Path("/tmp/v2-candidates.txt");OUT=pathlib.Path("/tmp/v2-tested.txt")
nodes=list(dict.fromkeys(x.strip() for x in SRC.read_text().splitlines() if x.strip().startswith("trojan://")))
def direct_ip():
 r=subprocess.run(["curl","-4fsS","--max-time","10","https://api.ipify.org"],capture_output=True,text=True)
 return r.stdout.strip() if r.returncode==0 else ""
BASE_IP=direct_ip()
def port():
 s=socket.socket();s.bind(("127.0.0.1",0));p=s.getsockname()[1];s.close();return p
def curl(proxy,*args,timeout=15):
 return subprocess.run(["curl","-4fsS","--proxy",proxy,"--max-time",str(timeout),"--connect-timeout","6",*args],capture_output=True,text=True,timeout=timeout+2)
def test(node):
 u=urllib.parse.urlsplit(node)
 if not u.hostname or not u.port or not u.username:return None
 p=port();proxy=f"socks5h://127.0.0.1:{p}"
 cfg={"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":p,"protocol":"socks","settings":{"udp":False}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":u.hostname,"port":u.port,"password":urllib.parse.unquote(u.username)}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":u.hostname,"allowInsecure":False}}}]}
 with tempfile.TemporaryDirectory() as d:
  f=pathlib.Path(d)/"c.json";f.write_text(json.dumps(cfg));q=subprocess.Popen(["xray","run","-config",str(f)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   time.sleep(1);delays=[];exit_ip=""
   for round_no in range(3):
    started=time.monotonic()
    r=curl(proxy,"-o","/dev/null","-w","%{http_code}","https://www.gstatic.com/generate_204")
    if r.returncode or r.stdout.strip()!="204":return None
    ip=curl(proxy,"https://api.ipify.org").stdout.strip()
    if not ip or ip==BASE_IP:return None
    if exit_ip and ip!=exit_ip:return None
    exit_ip=ip
    data=curl(proxy,"-o","/dev/null","-w","%{http_code}:%{size_download}","https://speed.cloudflare.com/__down?bytes=131072",timeout=20)
    if data.returncode:return None
    code,size=(data.stdout.strip().split(":",1)+["0"])[:2]
    if code!="200" or int(float(size))<131072:return None
    delays.append((time.monotonic()-started)*1000)
    if round_no<2:time.sleep(3)
   base=node.split("#",1)[0]
   query=urllib.parse.urlencode({"security":"tls","type":"tcp","headerType":"none","sni":u.hostname})
   return statistics.median(delays),f"{base.split('?',1)[0]}?{query}",exit_ip
  except Exception:return None
  finally:
   q.terminate()
   try:q.wait(timeout=2)
   except subprocess.TimeoutExpired:q.kill()
print("strict testing",len(nodes),"nodes; direct IP",BASE_IP,flush=True)
passed=[]
with ThreadPoolExecutor(max_workers=4) as ex:
 for f in as_completed([ex.submit(test,n) for n in nodes]):
  r=f.result()
  if r:passed.append(r);print("REAL PASS",r[2],flush=True)
passed.sort()
OUT.write_text("\n".join(n+f"#%E6%96%B0%E5%8A%A0%E5%9D%A1%20{i}" for i,(_,n,_) in enumerate(passed,1))+("\n" if passed else ""))
print("strict passed",len(passed),"of",len(nodes),"saved",OUT,flush=True)
if not passed:raise SystemExit("no node passed; old -V2 preserved")
