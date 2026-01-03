import time
from open_fprintd import FprintDevice, EnrollProgress
from egis_driver import EgisDriver
from matcher import FingerprintMatcher # Your SIFT matcher from before

class EgisPlugin(FprintDevice):
    def __init__(self):
        super().__init__()
        self.name = "Egis eh575 Sensor"
        self.driver = EgisDriver()
        self.matcher = FingerprintMatcher()
        self._scanning = False

    def enroll_finger(self, finger_name):
        """
        Generator that controls the GNOME enrollment UI.
        """
        self._scanning = True
        
        # CONFIG: How many scans do you want GNOME to ask for?
        TOTAL_SCANS = 10 
        
        enrolled_frames = []
        
        for i in range(1, TOTAL_SCANS + 1):
            # 1. Tell GNOME to ask user for touch
            # (In open-fprintd, yielding EnrollProgress does this)
            yield EnrollProgress(finger_name, i, TOTAL_SCANS)
            
            print(f"[PLUGIN] Waiting for scan {i}/{TOTAL_SCANS}...")
            
            # 2. Call our driver to get ONE scan
            # It will loop internally until it sees a finger
            scan = self.driver.capture_frame(timeout_sec=30)
            
            if scan:
                enrolled_frames.append(scan)
                print(f"[PLUGIN] Captured scan {i}")
                
                # Wait for user to lift finger (simple delay or loop until contrast drops)
                time.sleep(1.0) 
            else:
                print("[PLUGIN] Timed out waiting for finger")
                break
        
        # 3. Save the enrolled data
        if enrolled_frames:
            self.matcher.enroll_finger(finger_name, enrolled_frames)
            
        self._scanning = False

    def verify_finger(self, finger_name):
        self._scanning = True
        
        # Try to find a match for 30 seconds
        start = time.time()
        while time.time() - start < 30:
            scan = self.driver.capture_frame(timeout_sec=1)
            if scan:
                match, score = self.matcher.verify_finger(scan)
                if match == finger_name and score > 15:
                    self._scanning = False
                    return True # Success!
        
        self._scanning = False
        return False