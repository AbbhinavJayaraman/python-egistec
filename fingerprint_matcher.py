import cv2
import numpy as np
import os

class FingerprintMatcher:
    def __init__(self, enroll_dir="enrolled_fingers"):
        self.enroll_dir = enroll_dir
        if not os.path.exists(enroll_dir):
            os.makedirs(enroll_dir)
        # SIFT is robust for small, rotated partials. 
        # (Requires opencv-python or opencv-contrib-python)
        self.sift = cv2.SIFT_create()
        self.matcher = cv2.BFMatcher() # Brute Force Matcher

    def _preprocess(self, img_array):
        """Enhances ridges and contrast."""
        # Normalize to 0-255
        img = cv2.normalize(img_array, None, 0, 255, cv2.NORM_MINMAX).astype('uint8')
        # Histogram Equalization (Boost contrast)
        img = cv2.equalizeHist(img)
        # Optional: Gaussian Blur to remove sensor noise
        img = cv2.GaussianBlur(img, (3, 3), 0)
        return img

    def enroll_finger(self, name, raw_frames):
        """
        Saves the best features from a list of captured raw byte frames.
        raw_frames: list of bytes (5147 bytes each)
        """
        descriptors_list = []
        for raw in raw_frames:
            # Convert raw bytes to numpy image (103x50)
            img_arr = np.array(list(raw), dtype=np.uint8).reshape((50, 103)) # Check height/width order!
            img = self._preprocess(img_arr)
            
            # Detect keypoints and descriptors
            kp, des = self.sift.detectAndCompute(img, None)
            if des is not None:
                descriptors_list.append(des)
        
        if descriptors_list:
            # Save all descriptors for this finger to a file
            np.save(os.path.join(self.enroll_dir, f"{name}.npy"), descriptors_list)
            print(f"[ENROLL] Saved {len(descriptors_list)} templates for {name}")
            return True
        return False

    def verify_finger(self, raw_frame):
        """
        Compares a single frame against all enrolled fingers.
        Returns: (Name, Score) or None
        """
        img_arr = np.array(list(raw_frame), dtype=np.uint8).reshape((50, 103))
        img = self._preprocess(img_arr)
        kp, des = self.sift.detectAndCompute(img, None)
        
        if des is None: return None

        best_score = 0
        best_match = None

        # Compare against every enrolled file
        for filename in os.listdir(self.enroll_dir):
            if not filename.endswith(".npy"): continue
            
            name = filename.replace(".npy", "")
            enrolled_templates = np.load(os.path.join(self.enroll_dir, filename), allow_pickle=True)
            
            # Check against every template in the enrollment (Multi-template matching)
            for template_des in enrolled_templates:
                if template_des is None or len(template_des) < 2: continue
                
                # KNN Match with Ratio Test (Lowe's Ratio)
                matches = self.matcher.knnMatch(des, template_des, k=2)
                
                good_points = 0
                for m, n in matches:
                    if m.distance < 0.75 * n.distance:
                        good_points += 1
                
                # Scoring: How many features matched?
                if good_points > best_score:
                    best_score = good_points
                    best_match = name

        # Threshold (Adjust based on testing. 5-10 is usually a 'maybe', 20+ is strong)
        if best_score > 10: 
            return best_match, best_score
        return None, 0