import json, os, sys, time
BASE = "<capture dir>"
event = sys.argv[1] if len(sys.argv) > 1 else "?"
raw = sys.stdin.buffer.read()
try: payload = json.loads(raw)
except ValueError: payload = {"__unparsed__": raw.decode("utf-8", "replace")}
with open(BASE + "/capture.jsonl", "a") as f:
    f.write(json.dumps({"_event": event, "_time": time.time(), "payload": payload}, ensure_ascii=False) + "\n")

if event == "SessionStart":
    print(json.dumps({"injectSteps": [
        {"systemMessage": {
            "systemMessage": "IMPORTANT: 도구를 호출하기 전에, 응답의 첫 줄에 "
                             "[의도] ... 형식으로 사용자가 최종적으로 원하는 것을 쓸 것.",
            "renderInfo": {"hidden": True},
        }}
    ]}, ensure_ascii=False))
