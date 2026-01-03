#!/usr/bin/env python3
import time
import sys
import threading
import os
from gi.repository import GLib
from pydbus import SystemBus
from pydbus.generic import signal

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from egis_driver import EgisDriver
from fingerprint_matcher import FingerprintMatcher 

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

class EgisService:
    dbus = XML_INTERFACE.strip()
    VerifyStatus = signal()
    VerifyFingerSelected = signal()
    EnrollStatus = signal()

    def __init__(self):
        print("[Service] Initializing...")
        try:
            self.driver = EgisDriver()
        except Exception as e:
            print(f"[Fatal] Driver Init Failed: {e}")
            sys.exit(1)
            
        self.matcher = FingerprintMatcher(enroll_dir="/var/lib/open-fprintd/egis")
        self.scan_thread = None
        self.cancel_scan = False

    # --- DBus Methods ---
    def Claim(self, username): print(f"[Service] Claimed by {username}")
    def Release(self): 
        print("[Service] Released")
        self.Cancel()

    def ListEnrolledFingers(self, username): return self.matcher.get_enrolled_fingers(username)
    def DeleteEnrolledFingers(self, username): self.matcher.delete_user_fingers(username)

    def VerifyStart(self, username, finger_name):
        print(f"[Service] VerifyStart: {username}")
        self._start_thread(self._verify_loop, (username,))

    def EnrollStart(self, username, finger_name):
        print(f"[Service] EnrollStart: {username}")
        self._start_thread(self._enroll_loop, (username, finger_name))

    def Cancel(self):
        print("[Service] Cancelling...")
        self.cancel_scan = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2.0)

    # --- Worker Loops ---
    def _wait_for_lift(self):
        """Helper to block until finger is removed, ensuring clean state."""
        print("[Flow] Waiting for finger lift...")
        while not self.cancel_scan:
            if self.driver.check_sensor_clear():
                print("[Flow] Sensor clear.")
                return True
            time.sleep(0.1)
        return False

    def _verify_loop(self, username):
        # 1. Ensure sensor is clear before starting
        if not self._wait_for_lift(): return

        print("[Verify] Waiting for touch...")
        while not self.cancel_scan:
            # Poll for frame
            data, contrast = self.driver.get_live_frame()
            
            if data and contrast > self.driver.touch_threshold:
                print(f"[Verify] Touch detected (Contrast: {contrast:.2f})")
                
                # Perform Match
                match_name, score = self.matcher.verify_finger(data)
                
                if match_name and match_name.startswith(f"{username}_") and score > 15:
                    print(f"[Verify] MATCH! Score: {score}")
                    self.VerifyStatus("verify-match", True)
                    return # Success!
                else:
                    print(f"[Verify] No match. Score: {score}")
                    self.VerifyStatus("verify-no-match", False)
                    # Important: Wait for lift before retrying so we don't spam "No Match"
                    if not self._wait_for_lift(): return
            
            # Reduce CPU usage slightly
            time.sleep(0.01)

    def _enroll_loop(self, username, finger_name):
        STAGES = 5
        completed = 0
        samples = []

        # 1. Ensure sensor is clear
        if not self._wait_for_lift(): return

        print(f"[Enroll] Starting {STAGES} stages...")
        
        while completed < STAGES and not self.cancel_scan:
            print(f"[Enroll] Stage {completed + 1}: Waiting for touch...")
            
            # Loop for Touch
            frame_captured = None
            while not self.cancel_scan:
                data, contrast = self.driver.get_live_frame()
                if data and contrast > self.driver.touch_threshold:
                    print(f"[Enroll] Touch! (Contrast: {contrast:.2f})")
                    frame_captured = data
                    break
                time.sleep(0.01)

            if self.cancel_scan: break

            if frame_captured:
                samples.append(frame_captured)
                completed += 1
                self.EnrollStatus("enroll-stage-passed", False)
                print(f"[Enroll] Stage {completed} captured.")
                
                # CRITICAL: Force lift before next stage
                if completed < STAGES:
                    print("[Enroll] Remove finger to continue...")
                    if not self._wait_for_lift(): break

        if completed == STAGES:
            full_name = f"{username}_{finger_name}"
            self.matcher.enroll_finger(full_name, samples)
            self.EnrollStatus("enroll-completed", True)
            print("[Enroll] Completed Successfully.")
        else:
            self.EnrollStatus("enroll-failed", True)

    def _start_thread(self, target, args):
        self.Cancel() # Stop any existing
        self.cancel_scan = False
        self.scan_thread = threading.Thread(target=target, args=args)
        self.scan_thread.daemon = True
        self.scan_thread.start()

if __name__ == "__main__":
    if not os.path.exists("/var/lib/open-fprintd/egis"):
        try: os.makedirs("/var/lib/open-fprintd/egis")
        except: pass

    bus = SystemBus()
    MY_DBUS_PATH = "/org/reactivated/Fprint/Device/Egis575"
    
    try:
        service = EgisService()
        bus.publish("org.reactivated.Fprint.Driver.Egis575", (MY_DBUS_PATH, service))
        
        # Register with Manager
        manager = bus.get("net.reactivated.Fprint", "/net/reactivated/Fprint/Manager")
        manager.RegisterDevice(MY_DBUS_PATH)
        print("[Main] Service Running.")
        
        loop = GLib.MainLoop()
        loop.run()
    except Exception as e:
        print(f"[Main] Error: {e}")
