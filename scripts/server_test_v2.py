#!/usr/bin/env python3
import json,os,pathlib,socket,subprocess,tempfile,time,urllib.parse,statistics
from concurrent.futures import ThreadPoolExecutor,as_completed
SRC=pathlib.Path("/tmp/v2-candidates.txt");OUT=pathlib.Path("/tmp/v2-tested.txt")
env={}
for line in pathlib.Path("/root/.config/github-v2/cn-proxy.env").read_text().splitlines():
 if "=" in line:
  k,v=line.split("=",1);env[k]=v
cn=urllib.parse.urlsplit(env["CN_PROXY"])
nodes=list(dict.fromkeys(x.strip() for x in SRC.read_text().splitlines() if x.strip().startswith("trojan://")))
def port():
 s=socket.socket();s.bind(("127.0.0.1",0));p=s.getsockname()[1];s.close();return p
def req(proxy,*args,timeout=20):
 return subprocess.run(["curl","-4fsS","--proxy",proxy,"--max-time",str(timeout),"--connect-timeout","8",*args],capture_output=True,text=True,timeout=timeout+2)
def test(node):
 u=urllib.parse.urlsplit(node)
 if not u.hostname or not u.port or not u.username:return None
 p=port();proxy=f"socks5h://127.0.0.1:{p}"
 cand={"tag":"candidate","protocol":"trojan","settings":{"servers":[{"address":u.hostname,"port":u.port,"password":urllib.parse.unquote(u.username)}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":u.hostname,"allowInsecure":False}},"proxySettings":{"tag":"cn","transportLayer":true}}
 cnout={"tag":"cn","protocol":"trojan","settings":{"servers":[{"address":cn.hostname,"port":cn.port,"password":urllib.parse.unquote(cn.username)}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":urllib.parse.parse_qs(cn.query).get("peer",[cn.hostname])[0],"allowInsecure":urllib.parse.parse_qs(cn.query).get("allowInsecure",["0"])[0]=="1"}}}
 cfg={"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":p,"protocol":"socks","settings":{"udp":False}}],"outbounds":[cand,cnout],"routing":{"rules":[{"type":"field","inboundTag":[],"outboundTag":"candidate"}]}}
 with tempfile.TemporaryDirectory() as d:
  f=pathlib.Path(d)/"c.json";f.write_text(json.dumps(cfg));q=subprocess.Popen(["xray","run","-config",str(f)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   time.sleep(1.2);ips=[];scores=[]
   for n in range(3):
    t=time.monotonic();r=req(proxy,"-o","/dev/null","-w","%{http_code}","https://www.gstatic.com/generate_204")
    if r.returncode or r.stdout.strip()!="204":return None
    ip=req(proxy,"https://api.ipify.org").stdout.strip()
    if not ip:return None
    dload=req(proxy,"-o","/dev/null","-w","%{http_code}:%{size_download}","https://speed.cloudflare.com/__down?bytes=262144",timeout=25)
    if dload.returncode:return None
    code,size=(dload.stdout.strip().split(":",1)+["0"])[:2]
    if code!="200" or int(float(size))<262144:return None
    ips.append(ip);scores.append((time.monotonic()-t)*1000)
    if n<2:time.sleep(4)
