# Independent fictional administrative peer. No sudo, privileged paths or VPN.
import json, os, select, socket, sys, time
mode, marker = sys.argv[1:]
s = socket.socket(fileno=0)
assert s.getsockname()=="" and s.getpeername()==""
assert os.getcwd()=="/" and os.environ["LANG"]=="C"
assert os.environ.get("VPNT_MUST_NOT_REACH_HELPER") is None
assert os.environ["SUDO_ASKPASS"]=="/Library/PrivilegedHelperTools/dev.vpnt.askpass"
assert os.environ["VPNT_AUTH_LOCALE"]=="pt-BR"
assert int(os.environ["VPNT_AUTH_UNTIL_NS"])>0
open(marker+".started","w").close()
def send(value):s.sendall(json.dumps(value).encode()+b"\n")
try:
    # A request sent before authentication is observable even in a late peer.
    if select.select([s],[],[],0.05)[0] and s.recv(1,socket.MSG_PEEK):
        open(marker+".early","w").close()
    if mode=="late":
        until=time.monotonic()+5
        while not os.path.exists(marker+".allow_ready") and time.monotonic()<until:
            if select.select([s],[],[],0.005)[0] and not s.recv(1,socket.MSG_PEEK):break
    send(dict(type="admin_ready",protocol_version=999 if mode=="protocol" else 2,version="old" if mode=="version" else "0.1.0"))
    open(marker+".ready","w").close()
    f=s.makefile("rb",buffering=0)
    line=f.readline()
    if line:
        request=json.loads(line)
        assert not f.read(1),"requires document plus EOF"
        assert request["command"]["type"]=="save_profile"
        assert request["command"]["profile"]["id"]=="one"
        open(marker+".received","w").close()
        if mode=="busy":send(dict(type="failed",id=request["id"],error="profile_busy"))
        else:
            send(dict(type="accepted",id="wrong" if mode=="wrong" else request["id"]))
            if mode=="duplicate":send(dict(type="accepted",id=request["id"]))
except (BrokenPipeError,ConnectionResetError):
    pass
if 'f' in locals():f.close()
s.close()
open(marker+".retiring","w").close()
if mode=="hold":
    until=time.monotonic()+5
    while not os.path.exists(marker+".allow_exit") and time.monotonic()<until:time.sleep(0.005)
time.sleep(0.1)
open(marker+".cleaned","w").close()
sys.exit(7 if mode=="exit" else 0)
