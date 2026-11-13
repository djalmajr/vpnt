# Fictional helper wire peer. No privilege, VPN, keychain or route operations.
import json, os, select, socket, sys, time
s = socket.socket(fileno=0)
assert s.type == socket.SOCK_STREAM and s.getsockname() == "" and s.getpeername() == ""
assert os.environ.get("VPNT_MUST_NOT_REACH_HELPER") is None
assert os.getcwd() == "/" and os.environ["LANG"] == "C"
mode, marker = sys.argv[1:]
f = s.makefile("rb",buffering=0)
def send(value):
    s.sendall(json.dumps(value).encode() + b"\n")
def changed(id, generation, state):
    previous=states.get(id,{})
    failures=min(previous.get("failures",0)+1,3) if state=="unresponsive" and previous.get("generation")==generation else (1 if state=="unresponsive" else 0)
    if generation>=states.get(id,dict(generation=0))["generation"]:
        states[id]=dict(id=id,generation=generation,state=state,failures=failures)
        with open(marker+".states","w") as out:json.dump(states,out)
    send(dict(type="changed", profile_id=id, generation=generation, state=state, failures=failures))
profiles=[dict(id=id,name=id,kind="ssl",gateway="vpn.example.test",username="fictional",networks=["10.20.0.0/24"],port=443,certificate="",probeHost="10.20.0.15",probePort=8443,probeMethod="tcp") for id in ["one","two"]]
if mode in ["ipsec","ipsec-denied"]:
    profiles.append(dict(id="ipsec",name="ipsec",kind="ipsec",gateway="vpn.example.test",username="fictional",networks=["10.20.0.0/24"],port=500,certificate="",probeHost="10.20.0.15",probePort=8443,probeMethod="tcp"))
states={p["id"]:dict(id=p["id"],generation=0,state="off",failures=0) for p in profiles}
waiting=[]
s.settimeout(10)
while True:
    if mode=="restart" and os.path.exists(marker+".fault"):
        s.sendall(b'{"type":"accepted","id":"wrong","extra":"invalid"}\n')
        mode="retiring"
    if waiting and os.path.exists(marker+".advance"):
        for id,generation in waiting:
            changed(id,generation,"verifying");changed(id,generation,"connected")
        waiting=[]
    if os.path.exists(marker+".close"):
        break
    if os.path.exists(marker+".stale"):
        with open(marker+".stale") as data:stale=json.load(data)
        send(dict(type="changed",profile_id=stale["id"],generation=stale["generation"],state=stale.get("state","unresponsive"),failures=stale.get("failures",3)))
        os.replace(marker+".stale",marker+".stale.sent")
    if not select.select([s],[],[],0.01)[0]:
        continue
    line=f.readline()
    if not line:
        break
    request=json.loads(line);command=request["command"]
    with open(marker+".commands","a") as record:
        record.write(command["type"]+"\n")
    if command["type"]=="snapshot":
        if mode=="malformed":
            s.sendall(b'{"type":"accepted","id":"wrong","password":"fictional"}\n');continue
        if mode=="old2":
            # A genuine protocol-2 body: TunnelStatus carried no `failures`.
            send(dict(type="snapshot",id=request["id"],protocol_version=2,version="0.1.0",profiles=profiles,connections=[dict(id=p["id"],generation=0,state="off") for p in profiles]))
            continue
        if os.path.exists(marker+".catalog"):
            with open(marker+".catalog") as data:new_profiles=json.load(data)
            old={p["id"]:p for p in profiles}
            for p in new_profiles:
                if p["id"] in old and p!=old[p["id"]]:
                    current=states.get(p["id"],dict(generation=0))
                    states[p["id"]]=dict(id=p["id"],generation=current["generation"]+1,state="off",failures=0)
            profiles=new_profiles
        send(dict(type="snapshot",id=request["id"],protocol_version=999 if mode=="protocol" else (2 if mode=="old" else 3),version="old" if mode=="version" else "0.1.0",profiles=profiles,connections=[dict(id=p["id"],generation=0,state="connected",failures=0) if mode=="unearned" else states.get(p["id"],dict(id=p["id"],generation=0,state="off",failures=0)) for p in profiles]))
    elif command["type"]=="connect":
        assert command["credentials"]["password"]=="fictional-client-secret"
        with open(marker+".intervals","a") as out:out.write(json.dumps(dict(type="connect",id=command["id"],generation=command["generation"],interval=command["interval"]))+"\n")
        connected_profile=next(p for p in profiles if p["id"]==command["id"])
        if connected_profile["kind"]=="ipsec":
            assert command["credentials"]["psk"]=="fictional-psk"
            if mode=="ipsec-denied":
                with open(marker+".denied","w") as out:json.dump(dict(id=request["id"],generation=command["generation"],error="missing_program"),out)
                send(dict(type="failed",id=request["id"],error="missing_program"))
                continue
        if os.path.exists(marker+".deny_connect"):
            with open(marker+".denied","w") as out:json.dump(dict(id=request["id"],generation=command["generation"],error="missing_program"),out)
            send(dict(type="failed",id=request["id"],error="missing_program"))
            continue
        if mode=="exit":
            break
        send(dict(type="accepted",id=request["id"]))
        changed(command["id"],command["generation"],"connecting")
        waiting.append((command["id"],command["generation"]))
    elif command["type"]=="disconnect":
        send(dict(type="accepted",id=request["id"]))
        changed(command["id"],command["generation"],"off")
    elif command["type"]=="set_probe_interval":
        assert command["interval"] in [10,30,60]
        with open(marker+".intervals","a") as out:out.write(json.dumps(dict(type="set_probe_interval",interval=command["interval"]))+"\n")
        send(dict(type="accepted",id=request["id"]))
    elif command["type"]=="probe":
        send(dict(type="accepted",id=request["id"]))
        changed(command["id"],command["generation"],"connected" if os.path.exists(marker+".probe_ok") else "unresponsive")
    else:
        raise AssertionError("unexpected fixture command")
open(marker+".retiring","w").close()
if mode in ["malformed","retiring"]:
    until=time.monotonic()+5
    while not os.path.exists(marker+".allow_cleanup") and time.monotonic()<until:
        time.sleep(0.005)
time.sleep(0.15)
open(marker+".cleaned","w").close()
