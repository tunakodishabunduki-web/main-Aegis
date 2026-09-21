#!/usr/bin/env python3
"""
physical_tracker.py
============================================================
Optional Aegis module: Physical Person Tracker (YOLOv5)

WHEN IT WORKS:
  - Attacker is physically present in a camera-covered area
    (kiosk, office reception, server room entrance, lab)
  - You are running penetration tests on your own systems
    and want to correlate cyber events with physical presence

WHEN IT DOES NOT WORK:
  - Remote internet attacker — you have no camera on their side
  - You cannot access someone else's webcam without consent
  - This is NOT a surveillance tool — use only in authorised
    environments with proper signage and legal permission

INTEGRATION WITH AEGIS:
  PHP calls this module via PythonBridge when severity >= threshold.
  The tracker runs as a long-lived background process and receives
  trigger signals through a JSON flag file in /tmp/.

  Start the tracker once:
    python3 physical_tracker.py --source 0 --view-img

  Aegis PHP signals it via:
    python3 physical_tracker.py --trigger '{"ip":"41.x","severity":90}'

Dependencies:
  pip install torch torchvision opencv-python
  pip install git+https://github.com/ultralytics/yolov5

Usage:
  # Run tracker (long-lived, with display)
  python3 physical_tracker.py --source 0 --view-img --save-video

  # Trigger from command line (simulates PHP signal)
  python3 physical_tracker.py --trigger '{"ip":"41.222.13.87","severity":90}'

  # Ping (status check for dashboard)
  python3 physical_tracker.py --args '{"action":"ping"}'
  python3 physical_tracker.py --args '{"action":"status"}'
============================================================
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Signal file paths ──────────────────────────────────────────
# PHP writes here; tracker reads it on each frame to check for triggers
SIGNAL_FILE    = "/tmp/aegis_tracker_signal.json"
STATUS_FILE    = "/tmp/aegis_tracker_status.json"
SNAPSHOT_DIR   = Path(os.environ.get("AEGIS_SNAPSHOT_DIR", "/tmp/aegis_snapshots"))

# ── Configuration ──────────────────────────────────────────────
WEIGHTS    = "yolov5s.pt"   # downloaded automatically on first run
IMG_SIZE   = 640
CONF_THRES = 0.40
IOU_THRES  = 0.45
PERSON_CLS = 0              # COCO class 0 = person


# ── Tracker state (shared across loop iterations) ──────────────
class TrackerState:
    active        = False
    attacker_info = None
    snapshot_saved = False
    start_time    = None
    total_frames  = 0
    person_frames = 0


state = TrackerState()


# ══════════════════════════════════════════════════════════════
# SIGNAL HANDLING  (PHP → Python IPC via JSON file)
# ══════════════════════════════════════════════════════════════

def write_signal(attacker_data: dict) -> None:
    """PHP calls this by writing to SIGNAL_FILE via the tracker's --trigger flag."""
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "active":        True,
        "attacker":      attacker_data,
        "triggered_at":  datetime.now().isoformat(),
        "snapshot_saved": False,
    }
    with open(SIGNAL_FILE, "w") as f:
        json.dump(payload, f)
    print(json.dumps({"status": "signal_written", "attacker": attacker_data}))


def read_signal() -> dict | None:
    """Called on each frame to check if PHP has sent a trigger."""
    if not os.path.exists(SIGNAL_FILE):
        return None
    try:
        with open(SIGNAL_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def clear_signal() -> None:
    if os.path.exists(SIGNAL_FILE):
        os.remove(SIGNAL_FILE)


def write_status(data: dict) -> None:
    with open(STATUS_FILE, "w") as f:
        json.dump(data, f)


def read_status() -> dict:
    if not os.path.exists(STATUS_FILE):
        return {"running": False}
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"running": False, "error": "Could not read status file"}


# ══════════════════════════════════════════════════════════════
# DRAWING HELPERS
# ══════════════════════════════════════════════════════════════

def draw_target(frame, box, conf, name, center, offset, fps):
    """Draw the primary tracked person — green ring + crosshair + info box."""
    import cv2
    x1, y1, x2, y2 = map(int, box)
    cx, cy = center
    radius = max((x2 - x1 + y2 - y1) // 4, 20)

    # Ring
    cv2.circle(frame, (cx, cy), radius, (0, 255, 0), 3)
    cv2.circle(frame, (cx, cy), 5, (0, 255, 0), -1)
    # Crosshair
    cv2.line(frame, (cx - 18, cy), (cx + 18, cy), (0, 255, 0), 2)
    cv2.line(frame, (cx, cy - 18), (cx, cy + 18), (0, 255, 0), 2)
    # Bounding box
    cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
    cv2.putText(frame, f"{name} {conf:.2f}", (x1, max(y1 - 10, 20)),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)

    # Info panel
    _draw_info_panel(frame, cx, cy, offset, fps)

    # Attacker overlay (shown in red when triggered from Aegis)
    if state.attacker_info:
        ip  = state.attacker_info.get("ip", "unknown")
        sev = state.attacker_info.get("severity", "?")
        cv2.putText(frame, f"AEGIS ALERT — IP: {ip}  Severity: {sev}%",
                    (10, 115), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
        elapsed = int(time.time() - (state.start_time or time.time()))
        cv2.putText(frame, f"Tracking for {elapsed}s",
                    (10, 138), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)


def _draw_info_panel(frame, cx, cy, offset, fps):
    import cv2
    bx, by, bw, bh = 10, 10, 290, 100
    cv2.rectangle(frame, (bx, by), (bx + bw, by + bh), (0, 0, 0), -1)
    cv2.rectangle(frame, (bx, by), (bx + bw, by + bh), (0, 255, 0), 2)
    cv2.putText(frame, f"Target: ({cx}, {cy})",
                (bx + 8, by + 26), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)
    cv2.putText(frame, f"Offset  X:{offset[0]:+.0f}  Y:{offset[1]:+.0f}",
                (bx + 8, by + 52), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)
    cv2.putText(frame, f"FPS: {fps:.1f}",
                (bx + 8, by + 78), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 0), 2)


def draw_secondary(frame, det, primary_box, names):
    """Draw non-primary detections in blue."""
    import cv2
    for *xyxy, conf, cls in det:
        if list(map(int, xyxy)) == list(map(int, primary_box)):
            continue
        x1, y1, x2, y2 = map(int, xyxy)
        cv2.rectangle(frame, (x1, y1), (x2, y2), (255, 100, 0), 2)
        cv2.putText(frame, f"{names[int(cls)]} {conf:.2f}",
                    (x1, max(y1 - 8, 15)), cv2.FONT_HERSHEY_SIMPLEX,
                    0.45, (255, 100, 0), 1)


def draw_center_cross(frame):
    import cv2
    h, w = frame.shape[:2]
    cx, cy = w // 2, h // 2
    cv2.line(frame, (cx - 28, cy), (cx + 28, cy), (200, 200, 200), 1)
    cv2.line(frame, (cx, cy - 28), (cx, cy + 28), (200, 200, 200), 1)
    cv2.circle(frame, (cx, cy), 4, (200, 200, 200), -1)
    return cx, cy


def save_snapshot(frame, attacker_info: dict) -> str | None:
    """Save one snapshot when tracking activates. Returns filepath."""
    import cv2
    if state.snapshot_saved:
        return None
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    ip   = attacker_info.get("ip", "unknown").replace(".", "-")
    ts   = int(time.time())
    path = SNAPSHOT_DIR / f"aegis_attacker_{ip}_{ts}.jpg"
    cv2.imwrite(str(path), frame)
    state.snapshot_saved = True
    print(f"[Aegis Tracker] Snapshot saved: {path}", flush=True)
    write_status({
        "running":        True,
        "tracking_active": True,
        "snapshot":       str(path),
        "attacker":       attacker_info,
        "saved_at":       datetime.now().isoformat(),
    })
    return str(path)


# ══════════════════════════════════════════════════════════════
# MAIN TRACKER LOOP
# ══════════════════════════════════════════════════════════════

def run_tracker(opt):
    """Long-lived tracking loop. Press q to quit."""
    import cv2
    import torch

    write_status({"running": True, "tracking_active": False,
                  "started_at": datetime.now().isoformat()})

    try:
        import yolov5
        model = yolov5.load(opt.weights)
        model.conf  = opt.conf_thres
        model.iou   = opt.iou_thres
        model.classes = [PERSON_CLS]
    except ImportError:
        print(json.dumps({"error": "yolov5 not installed — run: pip install yolov5"}))
        sys.exit(1)

    source = int(opt.source) if opt.source.isdigit() else opt.source
    cap    = cv2.VideoCapture(source)

    if not cap.isOpened():
        print(json.dumps({"error": f"Cannot open source: {opt.source}"}))
        sys.exit(1)

    print("[Aegis Tracker] Running. Press q to quit.", flush=True)

    vid_writer = None
    if opt.save_video:
        w   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 30
        out_path = str(SNAPSHOT_DIR / f"aegis_track_{int(time.time())}.mp4")
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        vid_writer = cv2.VideoWriter(out_path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h))

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        state.total_frames += 1
        h_f, w_f = frame.shape[:2]
        cx_frame, cy_frame = w_f // 2, h_f // 2
        t0 = time.time()

        # Check for signal from PHP/Aegis
        sig = read_signal()
        if sig and sig.get("active") and not state.active:
            state.active        = True
            state.attacker_info = sig.get("attacker", {})
            state.snapshot_saved = False
            state.start_time    = time.time()
            print(f"[Aegis Tracker] ACTIVATED — {state.attacker_info}", flush=True)

        # Inference
        results = model(frame, size=opt.img_size)
        dets    = results.xyxy[0].cpu().numpy()     # [x1,y1,x2,y2,conf,cls]
        fps_val = 1.0 / max(time.time() - t0, 1e-6)

        person_dets = [d for d in dets if int(d[5]) == PERSON_CLS]
        target_found = bool(person_dets)

        if person_dets:
            state.person_frames += 1
            person_dets.sort(key=lambda d: d[4], reverse=True)
            primary  = person_dets[0]
            box      = primary[:4]
            conf     = float(primary[4])
            x1, y1, x2, y2 = map(int, box)
            center   = ((x1 + x2) // 2, (y1 + y2) // 2)
            offset   = (center[0] - cx_frame, center[1] - cy_frame)

            draw_target(frame, box, conf, "Person", center, offset, fps_val)
            if len(person_dets) > 1:
                draw_secondary(frame, dets, box, {0: "Person"})

            if state.active:
                save_snapshot(frame, state.attacker_info)
        else:
            import cv2 as _cv2
            _cv2.putText(frame, "No person detected", (10, 30),
                         cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)

        draw_center_cross(frame)

        # Status bar at bottom
        status_txt = ("TRACKING ACTIVE" if state.active else "Monitoring") + \
                     f"  |  Frames:{state.total_frames}  Persons:{state.person_frames}"
        cv2.putText(frame, status_txt, (10, h_f - 12),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.45, (180, 180, 180), 1)

        if opt.view_img:
            cv2.imshow("Aegis Physical Tracker", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

        if vid_writer:
            vid_writer.write(frame)

    # Cleanup
    cap.release()
    if vid_writer:
        vid_writer.release()
    cv2.destroyAllWindows()
    write_status({"running": False, "stopped_at": datetime.now().isoformat()})


# ══════════════════════════════════════════════════════════════
# CLI  (handles both long-lived run AND single-shot actions)
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Aegis Physical Tracker")
    parser.add_argument("--weights",    default=WEIGHTS)
    parser.add_argument("--source",     default="0")
    parser.add_argument("--img-size",   type=int, default=IMG_SIZE)
    parser.add_argument("--conf-thres", type=float, default=CONF_THRES)
    parser.add_argument("--iou-thres",  type=float, default=IOU_THRES)
    parser.add_argument("--device",     default="")
    parser.add_argument("--view-img",   action="store_true")
    parser.add_argument("--save-video", action="store_true")
    # Single-shot flags used by PythonBridge
    parser.add_argument("--trigger",    default=None,
                        help="JSON attacker info — write signal file and exit")
    parser.add_argument("--args",       default=None,
                        help="JSON action payload (ping / status) used by PythonBridge")
    opt = parser.parse_args()

    # Single-shot: called by PythonBridge for ping/status
    if opt.args:
        try:
            params = json.loads(opt.args)
        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid --args JSON"}))
            sys.exit(1)

        action = params.get("action", "status")
        if action == "ping":
            print(json.dumps({"status": "available",
                              "note": "start with --source 0 --view-img to activate"}))
        elif action == "status":
            print(json.dumps(read_status()))
        else:
            print(json.dumps({"error": f"Unknown action: {action}"}))
        return

    # Single-shot: write trigger signal for a running tracker process
    if opt.trigger:
        try:
            attacker_data = json.loads(opt.trigger)
        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid --trigger JSON"}))
            sys.exit(1)
        write_signal(attacker_data)
        return

    # Long-lived tracker loop
    run_tracker(opt)


if __name__ == "__main__":
    main()
