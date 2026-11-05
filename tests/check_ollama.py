import json
import urllib.request

MODEL_NAME = "qwen2.5:7b"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

payload = {
    "model": MODEL_NAME,
    "prompt": "请只回复：PYTHON调用成功",
    "stream": False,
    "options": {
        "temperature": 0
    }
}

request = urllib.request.Request(
    OLLAMA_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

print("正在通过 Python 调用 Ollama，请稍候……")

with urllib.request.urlopen(request, timeout=180) as response:
    result = json.loads(response.read().decode("utf-8"))

print("模型名称：", result.get("model"))
print("模型回复：", result.get("response", "").strip())
print("PYTHON_OLLAMA_TEST=PASS")