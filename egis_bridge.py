import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import egis_driver
import time
import threading
import pickle
import os
import numpy as np

# --- Configuration ---
DEVICE_IFACE = 'io.github.uunicorn.Fprint.Device'
MANAGER_IFACE = 'net.reactivated.Fprint.Manager'
MANAGER_OBJ = '/net/reactivated/Fprint/Manager'
MANAGER_BUS = 'net.reactivated.Fprint'
STORAGE_FILE = "fingerprints.pkl"

class EgisBridge(dbus.service.Object):
    def __init__(self, bus):
        self.bus = bus
        self.path = "/org/reactivated/Fprint/Device/Egis"
        dbus.service.Object.__init__(self, bus, self.path)
        
        print("[BRIDGE] Initializing Driver...")
        self.driver = egis_driver.EgisDriver()
        self.scanning = False
        self.enroll_scans = []  # Temporary storage for current enrollment
        
        self.prints = self._load_prints()
        self._register_with_manager()

    def _load_prints(self):
        if os.path.exists(STORAGE_FILE):
            try:
                with open(STORAGE_FILE, 'rb') as f:
                    return pickle.load(f)
            except:
                return {}
        return {}

    def _save_prints(self):
        with open(STORAGE_FILE, 'wb') as f:
            pickle.dump(self.prints, f)
        print("[BRIDGE] Database saved.")

    def _register_with_manager(self):
        try:
            manager_proxy = self.bus.get_object(MANAGER_BUS, MANAGER_OBJ)
            manager = dbus.Interface(manager_proxy, MANAGER_IFACE)
            manager.RegisterDevice(self.path)
            print("[BRIDGE] Successfully registered with open-fprintd!")
        except Exception as e:
            print(f"[BRIDGE] Failed to register: {e}")

    # --- DBus Methods ---

    @dbus.service.method(DEVICE_IFACE, in_signature='ss', out_signature='')
    def VerifyStart(self, username, finger_name):
        print(f"[BRIDGE] Verify Requested for user: {username}")
        self.scanning = True
        threading.Thread(target=self._scan_loop, args=("verify", username)).start()

    @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
    def VerifyStop(self):
        print("[BRIDGE] Verify Stopped")
        self.scanning = False

    @dbus.service.method(DEVICE_IFACE, in_signature='ss', out_signature='')
    def EnrollStart(self, username, finger_name):
        print(f"[BRIDGE] Enroll Requested for user: {username}")
        self.enroll_scans = [] # Reset counter
        self.scanning = True
        threading.Thread(target=self._scan_loop, args=("enroll", username)).start()

    @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
    def EnrollStop(self):
        print("[BRIDGE] Enroll Stopped")
        self.scanning = False

    @dbus.service.method(DEVICE_IFACE, in_signature='', out_signature='')
    def Cancel(self):
        print("[BRIDGE] Cancel Requested")
        self.scanning = False

    @dbus.service.method(DEVICE_IFACE, in_signature='s', out_signature='as')
    def ListEnrolledFingers(self, username):
        if username in self.prints:
            print(f"[BRIDGE] Listing fingers for {username}: {list(self.prints[username].keys())}")
            return list(self.prints[username].keys())
        return []

    @dbus.service.method(DEVICE_IFACE, in_signature='s', out_signature='')
    def DeleteEnrolledFingers(self, username):
        print(f"[BRIDGE] Deleting prints for {username}")
        if username in self.prints:
            del self.prints[username]
            self._save_prints()

    # --- Logic Core ---
    
    def _wait_for_finger_release(self):
        """Blocks until the sensor is clear to prevent double-scanning."""
        print("[BRIDGE] Waiting for finger release...")
        while self.scanning:
            if self.driver.check_sensor_clear():
                print("[BRIDGE] Sensor clear.")
                return
            time.sleep(0.1)

    def _scan_loop(self, mode, username):
        print(f"[BRIDGE] Starting {mode} loop...")
        
        while self.scanning:
            # 1. Wait for finger touch
            if not self.driver.check_sensor_clear():
                print("[BRIDGE] Finger detected! Capturing...")
                
                # 2. Capture Frame
                img, contrast = self.driver.get_live_frame()
                if img is None: continue # Bad read

                print(f"[BRIDGE] Captured frame. Contrast: {contrast}")

                if mode == "enroll":
                    self._handle_enroll(img, username)
                elif mode == "verify":
                    self._handle_verify(img, username)
                
                # 3. CRITICAL: Wait for user to lift finger before next loop
                self._wait_for_finger_release()
            
            time.sleep(0.05)

    def _handle_enroll(self, img, username):
        # Add to temporary list
        self.enroll_scans.append(img)
        count = len(self.enroll_scans)
        print(f"[BRIDGE] Enroll Progress: {count}/5")

        if count < 5:
            # Tell GNOME "Good scan, lift finger and do it again"
            self.EnrollStatus("enroll-stage-passed", False)
        else:
            # We are done! Save everything.
            if username not in self.prints:
                self.prints[username] = {}
            
            # Save the list of 5 images as the "fingerprint"
            self.prints[username]["right-index-finger"] = self.enroll_scans
            self._save_prints()
            
            # Tell GNOME "All done"
            self.EnrollStatus("enroll-completed", True)
            self.scanning = False

    def _handle_verify(self, img, username):
        if username not in self.prints or "right-index-finger" not in self.prints[username]:
            print("[BRIDGE] No prints found for user!")
            self.VerifyStatus("verify-no-match", False)
            return

        saved_scans = self.prints[username]["right-index-finger"]
        
        # --- SIMPLE MATCHING LOGIC ---
        # Since we don't have the advanced matcher yet, we will do a 
        # simplistic check: Is the contrast similar? (Placeholder!)
        # REAL MATCHING should go here later.
        
        # For now, we assume if you pressed it, it's you (for testing flow)
        is_match = True 
        
        if is_match:
            print("[BRIDGE] MATCH FOUND!")
            self.VerifyStatus("verify-match", True)
            self.scanning = False
        else:
            print("[BRIDGE] No match.")
            self.VerifyStatus("verify-no-match", False)

    # --- Signals ---
    @dbus.service.signal(DEVICE_IFACE, signature='sb')
    def VerifyStatus(self, result, done):
        pass

    @dbus.service.signal(DEVICE_IFACE, signature='sb')
    def EnrollStatus(self, result, done):
        pass

if __name__ == '__main__':
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName("io.github.uunicorn.Fprint.Device.Egis", bus)
    device = EgisBridge(bus)
    loop = GLib.MainLoop()
    loop.run()
