# Fictional administrative writer for the application broker's subprocess tests.
import json,os,select,socket,sys,time
marker,mode=sys.argv[1:]
s=socket.socket(fileno=0)
open(marker+".admin_started","w").close()
try:
    until=time.monotonic()+5
    while not os.path.exists(marker+".authorize") and time.monotonic()<until:
        if select.select([s],[],[],0.005)[0]:
            if s.recv(1,socket.MSG_PEEK):raise AssertionError("document before ready")
            break
    s.sendall(b'{"type":"admin_ready","protocol_version":3,"version":"0.1.0"}\n')
    f=s.makefile('rb',buffering=0);line=f.readline()
    if line:
        request=json.loads(line);assert not f.read(1)
        command=request["command"]
        with open(marker+".catalog") as data:profiles=json.load(data)
        if mode=="reject":
            reply=dict(type="failed",id=request["id"],error="profile_busy")
        else:
            if command["type"]=="save_profile":
                profile=command["profile"];profiles=[p for p in profiles if p["id"]!=profile["id"]]+[profile]
            elif command["type"]=="remove_profile":profiles=[p for p in profiles if p["id"]!=command["id"]]
            else:raise AssertionError("closed administration modes")
            if mode!="lie":
                with open(marker+".catalog.tmp","w") as out:json.dump(profiles,out)
                os.chmod(marker+".catalog.tmp",0o600);os.replace(marker+".catalog.tmp",marker+".catalog")
            reply=dict(type="accepted",id=request["id"])
        s.sendall(json.dumps(reply).encode()+b'\n')
    f.close()
except (BrokenPipeError,ConnectionResetError):pass
s.close()
open(marker+".admin_retiring","w").close()
time.sleep(0.1)
open(marker+".admin_finished","w").close()
