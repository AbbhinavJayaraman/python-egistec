#!/usr/bin/env python3
import time
import sys
import threading
from gi.repository import GLib
from pydbus import SystemBus

# Import your actual driver logic
from egis_driver import EgisDriver
from matcher import FingerprintMatcher 

# The Interface open-fprintd expects backend drivers to speak
XML_INTERFACE = """
<node>
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

class EgisDBusService:
    dbus = XML_INTERFACE

    def __init__(self):
        print("[Service] Initializing Egis Hardware...")
        self.driver = EgisDriver() 
        self.matcher = FingerprintMatcher(enroll_dir="/var/lib/open-fprintd/egis")
        
        self.scan_thread = None
        self.cancel_scan = False

    # --- DBus Methods ---

    def Claim(self, username):
        # We don't really need to do anything for Claim with this hardware
        print(f"[Service] Claimed by {username}")
        pass

    def Release(self):
        print("[Service] Released")
        self._stop_scan_thread()

    def ListEnrolledFingers(self, username):
        # In a real implementation, ask matcher which files exist
        # For now, returning empty list or letting matcher handle it is fine
        # if the matcher had a list_fingers() method, we'd use it here.
        # But for 'open-fprintd', returning [] usually forces it to just assume logic.
        # Ideally: return self.matcher.get_enrolled_list(username)
        return []

    def DeleteEnrolledFingers(self, username):
        print(f"[Service] Deleting fingers for {username}")
        # self.matcher.delete_user(username)
        pass

    def VerifyStart(self, username, finger_name):
        print(f"[Service] Verify requested for {username}")
        self._start_thread(self._verify_loop, (username,))

    def EnrollStart(self, username, finger_name):
        print(f"[Service] Enroll requested for {username} (finger: {finger_name})")
        self._start_thread(self._enroll_loop, (username, finger_name))

    def Cancel(self):
        """
        Called by open-fprintd when the user cancels the operation
        or the GDM login screen times out.
        """
        print("[Service] Cancel requested")
        self._stop_scan_thread()

    # --- Internal Logic ---

    def _verify_loop(self, username):
        print("[Verify] Starting loop...")
        # Verify loop runs until match, cancel, or timeout (30s implied by GDM)
        while not self.cancel_scan:
            frame = self.driver.capture_frame(timeout_sec=0.5)
            if frame:
                match, score = self.matcher.verify_finger(frame)
                if match and score > 15:
                    print(f"MATCH! Score: {score}")
                    self.VerifyStatus("verify-match", True)
                    return
                else:
                    print("No match found.")
                    self.VerifyStatus("verify-no-match", False)
            # Sleep small amount if driver didn't block
            time.sleep(0.01)
            
        print("[Verify] Stopped.")

    def _enroll_loop(self, username, finger_name):
        # GNOME expects 5 stages by default (we can configure this in open-fprintd too)
        STAGES = 5
        completed = 0
        samples = []

        print(f"[Enroll] Starting {STAGES} stage enrollment...")

        while completed < STAGES and not self.cancel_scan:
            print(f"[Enroll] Waiting for finger (Stage {completed+1})...")
            
            # 1. Capture
            frame = self.driver.capture_frame(timeout_sec=1.0)
            if frame:
                samples.append(frame)
                completed += 1
                print(f"[Enroll] Stage {completed} captured.")
                self.EnrollStatus("enroll-stage-passed", False)
                
                # 2. Wait for lift (Debounce)
                time.sleep(1.0) 
            
        if not self.cancel_scan and completed == STAGES:
            print("[Enroll] All stages complete. Saving...")
            self.matcher.enroll_finger(f"{username}_{finger_name}", samples)
            self.EnrollStatus("enroll-completed", True)
        else:
            print("[Enroll] Cancelled or Failed.")
            self.EnrollStatus("enroll-failed", True)

    # --- Thread Helpers ---
    def _start_thread(self, target, args):
        self._stop_scan_thread()
        self.cancel_scan = False
        self.scan_thread = threading.Thread(target=target, args=args)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _stop_scan_thread(self):
        self.cancel_scan = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=1.0)

# --- BOOTSTRAP ---
if __name__ == "__main__":
    bus = SystemBus()
    
    # 1. Publish our object
    MY_DBUS_PATH = "/org/reactivated/Fprint/Device/Egis575"
    service = EgisDBusService()
    bus.publish("org.reactivated.Fprint.Driver.Egis575", [(MY_DBUS_PATH, service)])
    
    print("[Main] DBus Service Published. Registering with Open-Fprintd...")

    # 2. Tell open-fprintd we exist
    try:
        manager = bus.get("net.reactivated.Fprint.Manager")
        manager.RegisterDevice(MY_DBUS_PATH)
        print("[Main] SUCCESS: Registered with Manager!")
    except Exception as e:
        print(f"[Error] Could not register with Manager: {e}")
        print("Ensure 'open-fprintd' service is running and you have Polkit permissions!")
        sys.exit(1)

    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        pass