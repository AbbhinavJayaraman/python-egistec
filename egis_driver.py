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
        # Copied from continuous_driver: Give it time to boot after set_configuration
        print("[DRIVER] Device found. Waiting 1.0s for stability...")
        time.sleep(1.0) 
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
        except usb.core.USBError as e:
            print(f"[DRIVER] USB Error sending {hex_str}: {e}")
            pass
        return None

    def _initialize_sensor(self):
        print("[DRIVER] Initializing Hardware Sequence...")
        
        # 1. Factory Reset & Patching
        patches = [
            "45 47 49 53 60 00 06", "45 47 49 53 60 01 06", "45 47 49 53 60 40 06",
            "45 47 49 53 61 0a f4", "45 47 49 53 61 0c 44", "45 47 49 53 61 40 00",
            "45 47 49 53 60 40 00", "45 47 49 53 71 02 02 01 0c", "45 47 49 53 61 0c 22",
            "45 47 49 53 61 0b 03", "45 47 49 53 61 0a fc"
        ]
        for p in patches: self._send_hex(p)
        
        # 2. Unlock
        self._send_hex("45 47 49 53 60 00 fc")
        self._send_hex("45 47 49 53 60 01 fc")
        self._send_hex("45 47 49 53 60 41 fc")

        # 3. Init Blob
        init_cmds = [
            "45 47 49 53 97 00 00",
            "45 47 49 53 60 00 00", "45 47 49 53 60 00 00", "45 47 49 53 60 00 00",
            "45 47 49 53 60 00 00", "45 47 49 53 60 00 00",
            "45 47 49 53 60 01 00", "45 47 49 53 61 0a fd", "45 47 49 53 61 35 02",
            "45 47 49 53 61 80 00", "45 47 49 53 60 80 00", "45 47 49 53 61 0a fc",
            "45 47 49 53 63 01 02 0f 03", "45 47 49 53 61 0c 22", "45 47 49 53 61 09 83",
            "45 47 49 53 63 26 06 06 60 06 05 2f 06", "45 47 49 53 61 0a f4",
            "45 47 49 53 61 0c 44", "45 47 49 53 61 50 03", "45 47 49 53 60 50 03",
        ]
        for c in init_cmds: 
            self._send_hex(c)
            time.sleep(0.002)
        
        # 4. Final Setup
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
        self._send_hex("45 47 49 53 61 2d 20")
        self._send_hex("45 47 49 53 60 00 20")
        self._send_hex("45 47 49 53 60 01 20")
        self._send_hex("45 47 49 53 63 2c 02 00 57")
        self._send_hex("45 47 49 53 60 2d 02")
        self._send_hex("45 47 49 53 62 67 03")
        self._send_hex("45 47 49 53 63 2c 02 00 13")
        self._send_hex("45 47 49 53 60 00 02")

    def capture_frame(self, timeout_sec=10):
        start_time = time.time()
        
        while (time.time() - start_time) < timeout_sec:
            self._rearm()
            self.dev.write(ENDPOINT_OUT, bytes.fromhex("45 47 49 53 64 14 ec"))
            
            try:
                # Use the longer timeout from your working script
                data = self.dev.read(ENDPOINT_IN, 10000, timeout=1500)
                
                try: self.dev.read(ENDPOINT_IN, 512, timeout=50)
                except: pass

                if len(data) > 5000:
                    # Pad/Trim logic
                    target = IMG_WIDTH * IMG_HEIGHT
                    if len(data) < target: data += bytes(target - len(data))
                    else: data = data[:target]

                    # DEBUGGING: Print stats for every captured frame
                    arr = np.array(list(data), dtype=np.uint8)
                    contrast = np.std(arr)
                    print(f"[DEBUG] Read {len(data)} bytes. Contrast: {contrast:.2f}")

                    if contrast > 5.0:
                        print("[DEBUG] >>> FINGER ACCEPTED <<<")
                        return data
            
            except usb.core.USBError:
                # print("[DEBUG] USB Timeout (No finger?)")
                pass
            
        return None