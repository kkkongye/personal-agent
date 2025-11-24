import requests

API_KEY = "sk-HO6229N9hxExw4P0lj5wPRJnQX9Dr6IO1Pqlwb9WMgAWUMAk"
url = "https://poloai.top/v1/chat/completions"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}"
}

data = {
    "model": "gpt-4o",
    "messages": [
        {"role": "system", "content": "你是一个有用的助手"},
        {"role": "user", "content": "你好，测试一下API是否可用"}
    ],
    "max_tokens": 50
}

response = requests.post(url, headers=headers, json=data)

print("状态码:", response.status_code)
print("返回内容:", response.json())
