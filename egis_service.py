#!/usr/bin/env python3
import time
import sys
import threading
import os
import syslog
from gi.repository import GLib
from pydbus import SystemBus
from pydbus.generic import signal

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from egis_driver import EgisDriver
from fingerprint_matcher import FingerprintMatcher 

# --- CONFIGURATION ---
# CRITICAL FIX: The interface name MUST be net.reactivated.Fprint.Device
# or standard fprintd clients will not invoke methods on it.
XML_INTERFACE = """<node>
  <interface name="io.github.uunicorn.Fprint.Device">
    <method name="Claim">
      <arg direction="in" type="s" name="username"/>
    </method>
    <method name="Release">
    </method>
    <method name="VerifyStart">
      <arg direction="in" type="s" name="username"/>
      <arg direction="in" type="s" name="finger_name"/>
    </method>
    <method name="EnrollStart">
      <arg direction="in" type="s" name="username"/>
      <arg direction="in" type="s" name="finger_name"/>
    </method>
    <method name="Cancel">
    </method>
    <method name="ListEnrolledFingers">
      <arg direction="in" type="s" name="username"/>
      <arg direction="out" type="as" name="fingers"/>
    </method>
    <method name="DeleteEnrolledFingers">
      <arg direction="in" type="s" name="username"/>
    </method>
    
    <signal name="VerifyStatus">
      <arg type="s" name="result"/>
      <arg type="b" name="done"/>
    </signal>
    <signal name="VerifyFingerSelected">
      <arg type="s" name="finger"/>
    </signal>
    <signal name="EnrollStatus">
      <arg type="s" name="result"/>
      <arg type="b" name="done"/>
    </signal>
  </interface>
</node>
"""

def log(msg):
    """Writes to both stdout (for manual running) and syslog (for journalctl)."""
    syslog.syslog(syslog.LOG_NOTICE, f"[EgisDriver] {msg}")
    print(f"[EgisDriver] {msg}", flush=True)

class EgisService:
    dbus = XML_INTERFACE.strip()
    VerifyStatus = signal()
    VerifyFingerSelected = signal()
    EnrollStatus = signal()

    def __init__(self):
        log("Initializing Service...")
        try:
            self.driver = EgisDriver()
        except Exception as e:
            log(f"FATAL: Driver Init Failed: {e}")
            sys.exit(1)
            
        if not os.path.exists("/var/lib/open-fprintd/egis"):
            try: os.makedirs("/var/lib/open-fprintd/egis")
            except: pass
            
        self.matcher = FingerprintMatcher(enroll_dir="/var/lib/open-fprintd/egis")
        self.scan_thread = None
        self.cancel_scan = False
        log("Initialization Complete.")

    # --- DBus Methods ---
    def Claim(self, username): 
        log(f"Method: Claim called by {username}")

    def Release(self): 
        log("Method: Release called")
        self.Cancel()

    def ListEnrolledFingers(self, username): 
        fingers = self.matcher.get_enrolled_fingers(username)
        log(f"Method: ListEnrolledFingers -> {fingers}")
        return fingers

    def DeleteEnrolledFingers(self, username): 
        log(f"Method: DeleteEnrolledFingers for {username}")
        self.matcher.delete_user_fingers(username)

    def VerifyStart(self, username, finger_name):
        log(f"Method: VerifyStart for {username}")
        self._start_thread(self._verify_loop, (username,))

    def EnrollStart(self, username, finger_name):
        log(f"Method: EnrollStart for {username}")
        self._start_thread(self._enroll_loop, (username, finger_name))

    def Cancel(self):
        log("Method: Cancel called")
        self.cancel_scan = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2.0)

    # --- Worker Loops ---
    def _wait_for_lift(self):
        log("Waiting for lift...")
        consecutive_clears = 0
        
        while not self.cancel_scan:
            _, contrast = self.driver.get_live_frame()
            if contrast < self.driver.touch_threshold:
                consecutive_clears += 1
                if consecutive_clears >= 2:
                    log("Sensor clear. Ready.")
                    return True
            else:
                consecutive_clears = 0
                # Using syslog for high-frequency loop data might spam, 
                # so we only log if it seems stuck (every ~20 iterations/2 seconds?)
                # For now, let's keep it quiet unless needed.
            time.sleep(0.1)
        return False

    def _verify_loop(self, username):
        if not self._wait_for_lift(): return

        log("Entering Verify Loop...")
        while not self.cancel_scan:
            data, contrast = self.driver.get_live_frame()
            
            if data and contrast > self.driver.touch_threshold:
                log(f"Touch Detected! Contrast: {contrast:.2f}")
                
                match_name, score = self.matcher.verify_finger(data)
                
                if match_name and match_name.startswith(f"{username}_") and score > 15:
                    log(f"MATCH! Score: {score}")
                    self.VerifyStatus("verify-match", True)
                    return 
                else:
                    log(f"No Match. Score: {score}")
                    self.VerifyStatus("verify-no-match", False)
                    if not self._wait_for_lift(): return
            
            time.sleep(0.01)

    def _enroll_loop(self, username, finger_name):
        STAGES = 5
        completed = 0
        samples = []

        if not self._wait_for_lift(): return

        log(f"Starting Enrollment ({STAGES} stages)")
        
        while completed < STAGES and not self.cancel_scan:
            log(f"Waiting for finger (Stage {completed + 1})...")
            
            frame_captured = None
            while not self.cancel_scan:
                data, contrast = self.driver.get_live_frame()
                if data and contrast > self.driver.touch_threshold:
                    log(f"Captured Stage {completed + 1} (Contrast: {contrast:.2f})")
                    frame_captured = data
                    break
                time.sleep(0.01)

            if self.cancel_scan: break

            if frame_captured:
                samples.append(frame_captured)
                completed += 1
                self.EnrollStatus("enroll-stage-passed", False)
                
                if completed < STAGES:
                    log("Please lift finger...")
                    if not self._wait_for_lift(): break

        if completed == STAGES:
            full_name = f"{username}_{finger_name}"
            self.matcher.enroll_finger(full_name, samples)
            self.EnrollStatus("enroll-completed", True)
            log("Enrollment Success!")
        else:
            self.EnrollStatus("enroll-failed", True)

    def _start_thread(self, target, args):
        self.Cancel() 
        self.cancel_scan = False
        self.scan_thread = threading.Thread(target=target, args=args)
        self.scan_thread.daemon = True
        self.scan_thread.start()

if __name__ == "__main__":
    syslog.openlog("egis-driver", syslog.LOG_PID)
    log("Service process started.")

    bus = SystemBus()
    MY_DBUS_PATH = "/org/reactivated/Fprint/Device/Egis575"
    
    try:
        service = EgisService()
        bus.publish("org.reactivated.Fprint.Driver.Egis575", (MY_DBUS_PATH, service))
        
        manager = bus.get("net.reactivated.Fprint", "/net/reactivated/Fprint/Manager")
        manager.RegisterDevice(MY_DBUS_PATH)
        log("DBus Service Registered. Waiting for events...")
        
        loop = GLib.MainLoop()
        loop.run()
    except Exception as e:
        log(f"Main Error: {e}")