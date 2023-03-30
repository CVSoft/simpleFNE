#!/bin/usr/env python3

# simpleFNE, a debugging tool by CVSoft
# Licensed GPLv3

import argparse
import configparser
import queue
import re
import socket
import struct
import sys
import threading
##import traceback # debugging only
import time

COMMANDS = ["RPTACK", "RPTCL", "RPTL", "RPTK", "RPTO", "RPTC", "RPTPING",
            "RPTSL", "DMRD", "P25D", "TRNSDIAG", "TRNSLOG"]

re_CMD = re.compile("^([A-Z]+)")

DEFAULT_CONFIG = {
"FNE": {
 "ip":"ANY",
 "port":"54000",
 "endpoint_timeout":120
 }
}


def form_int(s):
    """Unpack a signed int from a bytearray"""
    if isinstance(s, str): s = s.encode("windows-1252", "replace")
    if len(s) < 4: raise IndexError
    return s[3]+s[2]*256+s[1]*65536+s[0]*16777216

def quick_hex(s):
    """Dump hex contents of a string/bytearray"""
    if type(s) == tuple: s = s[0] # did you pass recvfrom output in here?
    if isinstance(s, str): s = s.encode("windows-1252", "replace")
    return ' '.join(map(lambda q:"{:02X}".format(q), s))


class FNE(object):
    """FNE main class. Handle endpoints and shuffle data between then."""
    def __init__(self, cfg_fn=None):
        print("Starting SimpleFNE...")
        self.running = True
        cp = configparser.RawConfigParser()
        cp.read_dict(DEFAULT_CONFIG)
        if cfg_fn: cp.read(cfg_fn)
        ip = cp["FNE"]["ip"]
        if ip == "ANY": ip = ''
        port = cp.getint("FNE", "port", fallback=54000)
        self.endpoint_timeout = cp.getint("FNE", "endpoint_timeout",
                                          fallback=120)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(1) # permit a slow tick for KeyboardInterrupt catch
        print("Listening on {}:{}".format(ip, port))
        self.s.bind((ip, port))
        self.endpoints = {} # addr:last_seen pairs for pruning
        self.endpoint_flag = threading.Event()
        self.endpoint_flag.set()
        self.q = queue.Queue() # unprocessed messages go here
        f = FNEReceiver(self, self.s)
##        try: f.loop()
##        except KeyboardInterrupt: f.running = False
        self.t = threading.Thread(target=f.loop, daemon=True)
        self.t.start()
        try: self.loop()
        except KeyboardInterrupt:
            print("Caught Ctrl-C at console, shutting down...")
            self.running = False
            f.running = False
        self.shutdown()

    def loop(self):
        """Do housekeeping periodically, basically."""
        print("SimpleFNE: Ready!")
        while self.running:
            for x in range(100): time.sleep(0.1)
            self.prune_endpoints()
##            print("Have {} endpoints, killed {}"\
##                  .format(*self.prune_endpoints()))

    def shutdown(self):
        print("Sending closure notice to all endpoints...")
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        for target in self.endpoints:
            p = struct.pack(">I", self.endpoints[target].peer_id)[0]
##            self._send_cmd(b"MSTCL"+p, target)
            self.endpoints[target].q.put(b"MSTCL"+p)
        if self.endpoints: time.sleep(1.1) # wait for timeouts to expire
        for target in self.endpoints:
            self.running = False
        self.endpoint_flag.set() #not safe, but doesn't matter now much does it
        t = time.time()
        print("Closing connections...")
        while time.time()-t < 2 and self.prune_endpoints()[0] != 0:
            time.sleep(0.1)
        if self.endpoints:
            print("Couldn't close certain endpoints. Killing them!")
            kl = tuple(self.endpoints.keys())
            for k in kl:
                del self.endpoints[kl].t
                del self.endpoints[kl]
        print("Exited simpleFNE")

    def register_endpoint(self, target):
        """Add a new endpoint, or update an existing one"""
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        if target in self.endpoints:
            self.endpoints[target].ts = time.time()
##            print("Updated existing endpoint", target)
        else:
            self.endpoints[target] = FNEEndpoint(self, self.s, target)
            print("Added new endpoint", target)
        self.endpoint_flag.set()

    def prune_endpoints(self):
        """Remove endpoints that haven't talked in a while"""
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        now = time.time() # fewer system calls
        prune = []
        for k in self.endpoints:
            # tell idle endpoints to shut down
            if now - self.endpoints[k].ts > self.endpoint_timeout:
                self.endpoints[k].running = False
            # delete fully shut down endpoints...
            if self.endpoints[k].safe and not self.endpoints[k].running:
                prune.append(k)
        #... without changing dict size in a loop
        for k in prune:
            del self.endpoints[k]
        lep = len(self.endpoints)
        self.endpoint_flag.set()
        return (lep, len(prune))

    def send_cmd(self, target, msg):
        """Send a command to a (hopefully) registered endpoint"""
        # this is usually called from outside threads
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        res = self._send_cmd(target, msg)
        self.endpoint_flag.set()
        return res

    def _send_cmd(self, target, msg):
        """Send a command without thread safety checks"""
        # this is usually called from outside threads
        if target not in self.endpoints: return False
        self.endpoints[target].q.put(msg)
        return True

    def handle_msg(self):
        """Check the message queue and process a command"""
        # this is called from outside threads
        # retrieve message from queue
##        print("Handling message, qsize is", self.q.qsize())
        try: msg = self.q.get_nowait()
        except queue.Empty:
            print("Tried to handle a message but there's no message?")
            return
        self.q.task_done()
        # getattr sorcery to handle the frame structure
        msgs = msg[0].decode("ascii", "replace")
        assert len(msgs) >= 4, "Impossible! We got a msg len under 4 as str!"
        # why couldn't they use fixed-length command names?
        found_command = False
        for cmd in COMMANDS:
            if msgs.startswith(cmd):
                found_command = True
                if hasattr(self, "cmd_"+cmd):
                    self.register_endpoint(msg[1])
                    getattr(self, "cmd_"+cmd)(msg[0], msg[1])
                else:
                    print("Unhandled command", cmd, "encountered")
                break
        if not found_command:
            m = re_CMD.match(msgs) # guess the command name
            if m: msgs = m.group(1)
            else: msgs = msgs[:7][:msgs.find('\x00')]
            print("Unrecognized command", msgs)
##        print()

    def update_peer_id(self, target, peer_id):
        """Update the peer ID of an endpoint"""
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        if target in self.endpoints:
            if self.endpoints[target].peer_id != None and \
               self.endpoints[target].peer_id != peer_id:
                print("Peer ID of", target, "changed from",
                      self.endpoints[target].peer_id, "to", peer_id)
            self.endpoints[target].peer_id = peer_id
        self.endpoint_flag.set()

    def cmd_RPTL(self, msg, addr):
        """Repeater login command -- repeater wants ACK with challenge salt"""
        print("Received login request from", form_int(msg[4:8]))
        self.send_cmd(addr, b"RPTACK\x00\x00\x00\x00")

    def cmd_RPTK(self, msg, addr):
        """Repeater authentication command -- repeater wants ACK with its ID"""
        # authentication is for losers who don't trust their network security
        # we let all clients in
        print("Skipping authentication from", form_int(msg[4:8]))
        self.send_cmd(addr, b"RPTACK"+msg[4:8])

    def cmd_RPTC(self, msg, addr):
        """Repeater configuration update -- repeater wants ACK with its ID"""
        print("Got configuration from", form_int(msg[4:8]))
        self.send_cmd(addr, b"RPTACK"+msg[4:8])

    def cmd_RPTCL(self, msg, addr):
        """Repeater closing notice -- it wants a NAK with its ID?"""
        print("Got shutdown notice from", form_int(msg[5:9]))
        # we should probably prune this endpoint immediately
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        if addr in self.endpoints:
            self.endpoints[addr].running = False
        self.endpoint_flag.set()
        # pruning will eventually remove it when it is safe

    def cmd_RPTPING(self, msg, addr):
        """Pong a ping -- repeater wants MSTPONG with its ID"""
        # DVMFNE checks if an endpoint is auth'd, else it gets a NAK + ID
        # In simpleFNE, all endpoints are auth'd, so we don't even check
        print("Got pinged by", form_int(msg[7:11]))
        self.send_cmd(addr, b"MSTPONG"+msg[7:11])

    def cmd_TRNSDIAG(self, msg, addr):
        """Transfer diagnostics log -- nothing expected in return"""
##        print("Ignoring transfer diagnostics")
        pass

    def cmd_TRNSLOG(self, msg, addr):
        """Transfer log -- nothing expected in return"""
##        print("Ignoring transfer log")
        pass

    def _cmd_repeat(self, msg, addr):
        """Repeat digital voice/data traffic to all *other* endpoints"""
        self.endpoint_flag.wait()
        self.endpoint_flag.clear()
        for dst in self.endpoints:
            if addr == dst: continue
            self.endpoints[dst].q.put(msg)
        self.endpoint_flag.set()

    def cmd_P25D(self, msg, addr):
        """Send P25 data to all *other* endpoints"""
        print("Got P25 data from", form_int(msg[4:8]))
        self._cmd_repeat(msg, addr)

    def cmd_DMRD(self, msg, addr):
        """Send DMR data to all *other* endpoints"""
        print("Got DMR data from", form_int(msg[4:8]))
        self._cmd_repeat(msg, addr)


class FNEReceiver(object):
    """Serve non-blockingly"""
    def __init__(self, cb, s):
        self.running = True
        self.cb = cb # callback to talk to endpoints
        self.s = s # socket object

    def loop(self):
        """Code to run in a thread"""
        while self.running:
            try: msg = self.s.recvfrom(2048)
            except socket.timeout: continue
##            print(repr(msg[0]))
##            print(quick_hex(msg[0]))
##            print()
            if len(msg[0]) > 4:
                try: self.cb.q.put_nowait(msg)
                except queue.Full:
                    print("dropping packet; this should never happen!")
                self.cb.handle_msg()


class FNEEndpoint(object):
    """Asynchronously send data to an endpoint"""
    def __init__(self, cb, s, target):
        self.running = True
        self.ts = time.time() # presumably this endpoint is getting registered
        self.cb = cb
        self.q = queue.Queue()
        self.s = s
        self.target = target
        self.peer_id = None
        self.safe = False
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        """Receieve messages from queue and write them to endpoint"""
        while self.running:
            try: msg = self.q.get(timeout=1) # block if idle?
            except queue.Empty: continue
            self.q.task_done()
##            print("Sending to", self.target)
##            print(repr(msg))
##            print(quick_hex(msg))
            self.s.sendto(msg, self.target)
        self.safe = True

def main():
    ap = argparse.ArgumentParser(description="SimpleFNE by CVSoft")
    ap.add_argument("fn", nargs="?", default=None)
    a = ap.parse_args()
    f = FNE(cfg_fn=a.fn)

if __name__ == "__main__" and "idlelib.run" not in sys.modules: main()
