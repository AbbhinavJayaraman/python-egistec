import usb.core
import usb.util
import time
import numpy as np
import os
import sys

# --- Hardware Constants ---
VENDOR_ID = 0x1c7a
PRODUCT_ID = 0x0575
ENDPOINT_OUT = 0x01
ENDPOINT_IN = 0x82
IMG_WIDTH = 103
IMG_HEIGHT = 50 

class EgisDriver:
    def __init__(self):
        self.dev = self._find_device()
        self._initialize_sensor()
    
    def _find_device(self):
        dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
        if not dev:
            raise ValueError("Egis Sensor not found!")
        
        if dev.is_kernel_driver_active(0):
            try: dev.detach_kernel_driver(0)
            except: pass
        
        dev.set_configuration()
        return dev

    def _send_hex(self, hex_str, read_resp=True):
        cmd = bytes.fromhex(hex_str)
        try:
            self.dev.write(ENDPOINT_OUT, cmd)
            if read_resp:
                return self.dev.read(ENDPOINT_IN, 64, timeout=1000)
        except usb.core.USBError:
            pass
        return None

    def _initialize_sensor(self):
        """Runs the boot sequence once on startup."""
        print("[DRIVER] Initializing Hardware...")
        # (Shortened for readability - same hex codes as your working script)
        patches = [
            "45 47 49 53 60 00 06", "45 47 49 53 60 01 06", "45 47 49 53 60 40 06",
            "45 47 49 53 61 0a f4", "45 47 49 53 61 0c 44", "45 47 49 53 61 40 00",
            "45 47 49 53 60 40 00", "45 47 49 53 71 02 02 01 0c", "45 47 49 53 61 0c 22",
            "45 47 49 53 61 0b 03", "45 47 49 53 61 0a fc"
        ]
        for p in patches: self._send_hex(p)
        
        # Unlock
        self._send_hex("45 47 49 53 60 00 fc")
        self._send_hex("45 47 49 53 60 01 fc")
        self._send_hex("45 47 49 53 60 41 fc")

        # Init Blob (Simplified for length - insert your full init list here)
        self._send_hex("45 47 49 53 97 00 00")
        # ... Insert the rest of your init_cmds here ...
        
        # Final Setup
        final_cmds = [
            "45 47 49 53 60 40 ec", "45 47 49 53 61 0c 22", "45 47 49 53 61 0b 03",
            "45 47 49 53 61 0a fc", "45 47 49 53 60 40 fc",
            "45 47 49 53 63 09 0b 83 24 00 44 0f 08 20 20 01 05 12",
            "45 47 49 53 63 26 06 06 60 06 05 2f 06", "45 47 49 53 61 23 00",
            "45 47 49 53 61 24 33", "45 47 49 53 61 20 00", "45 47 49 53 61 21 66",
            "45 47 49 53 60 00 66", "45 47 49 53 60 01 66",
        ]
        for c in final_cmds: self._send_hex(c)
        print("[DRIVER] Hardware Ready.")

    def _rearm(self):
        """Prepares sensor for a SINGLE shot."""
        self._send_hex("45 47 49 53 61 2d 20") # Reset Prep
        self._send_hex("45 47 49 53 60 00 20") # HW Reset
        self._send_hex("45 47 49 53 60 01 20") # Mode Check
        self._send_hex("45 47 49 53 63 2c 02 00 57") # Config
        self._send_hex("45 47 49 53 60 2d 02") # Status
        self._send_hex("45 47 49 53 62 67 03") # Calib Check
        self._send_hex("45 47 49 53 63 2c 02 00 13") # Wake
        self._send_hex("45 47 49 53 60 00 02") # Ready

    def capture_frame(self, timeout_sec=10):
        """
        Polls the sensor until a finger is detected OR timeout expires.
        Returns: bytes (raw image) or None
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout_sec:
            # 1. Arm
            self._rearm()
            
            # 2. Trigger
            self.dev.write(ENDPOINT_OUT, bytes.fromhex("45 47 49 53 64 14 ec"))
            
            try:
                # 3. Read
                data = self.dev.read(ENDPOINT_IN, 10000, timeout=100)
                
                # Drain metadata
                try: self.dev.read(ENDPOINT_IN, 512, timeout=20)
                except: pass

                if len(data) > 5000:
                    # Check Contrast to see if it's a real finger or just noise
                    # (Simple math, no OpenCV needed here for speed)
                    arr = np.array(list(data[:IMG_WIDTH*IMG_HEIGHT]), dtype=np.uint8)
                    if np.std(arr) > 5.0:
                        return data # SUCCESS: Found a finger!
            
            except usb.core.USBError:
                pass
            
            # Wait a tiny bit before polling again to be nice to CPU
            time.sleep(0.05)
            
        return None # Timed out