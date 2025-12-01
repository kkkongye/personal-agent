import requests
import json
import time
from datetime import datetime

def test_web_search(api_key, question, model="gpt-4.1"):
    """
    测试 poloapi 联网搜索功能 - 修正版
    """
    
    url = "https://poloai.top/v1/responses"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    # 修正的请求体 - 使用 input 而不是 messages
    payload = {
        "model": model,
        "input": question,  # 关键修正：使用 input 字段
        "web_search": True,  # 启用联网搜索
        "max_tokens": 1000,
        "temperature": 0.7
    }
    
    print(f"🔍 测试问题: {question}")
    print(f"🤖 使用模型: {model}")
    print("🔄 正在发送请求...")
    
    try:
        start_time = time.time()
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        end_time = time.time()
        
        print(f"⏱️  请求耗时: {end_time - start_time:.2f}秒")
        print(f"📡 HTTP状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ 联网搜索成功！")
            print("=" * 60)
            
            # 提取回答内容
            if 'output' in result:
                answer = result['output']
                print(f"🤖 AI回答:\n{answer}")
            elif 'choices' in result and len(result['choices']) > 0:
                answer = result['choices'][0].get('message', {}).get('content', '')
                print(f"🤖 AI回答:\n{answer}")
            else:
                print("📋 完整响应:")
                print(json.dumps(result, indent=2, ensure_ascii=False))
            
            print("=" * 60)
            return result
        else:
            print(f"❌ 请求失败: {response.status_code}")
            print(f"错误信息: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ 错误: {e}")



def test_octopus_chat(question, host="http://localhost:9527"):
    """调用 Octopus /v1/chat，验证自然语言触发联网搜索智能体"""
    url = host.rstrip("/") + "/v1/chat"
    payload = {"message": question, "timestamp": datetime.now().isoformat()}
    print("🟣 调用 Octopus /v1/chat")
    r = requests.post(url, json=payload, timeout=30)
    print(f"📡 HTTP状态码: {r.status_code}")
    try:
        data = r.json()
        if data.get("success"):
            print("✅ Octopus 成功响应")
            print(data.get("response"))
        else:
            print("❌ Octopus 错误:", data.get("error"))
    except Exception:
        print("❌ Octopus 响应解析失败:", r.text)


def quick_test(api_key):
    """快速测试 - 使用确认可用的格式 + Octopus 通道"""
    question = "今天有哪些重要新闻？历史上今天发生过哪些事件？请简要回答。"
    print("🎯 方法1: 使用 input 字段（直连 PoloAI）")
    test_web_search(api_key, question)
    print("\n🎯 方法2: 通过 Octopus /v1/chat（自然语言启用联网搜索）")
    test_octopus_chat(question)
    

if __name__ == "__main__":
    # 替换为您的实际 API Key
    YOUR_API_KEY = "sk-KRZodchCe464pA4pYIzuzH77RcGybo7FUAA7qqFR3W1C5IZI"  # 请替换为真实的 API Key
    
    if YOUR_API_KEY != "sk-KRZodchCe464pA4pYIzuzH77RcGybo7FUAA7qqFR3W1C5IZI":
        print("⚠️  请先替换脚本中的 YOUR_API_KEY 为您的真实 API Key")
    else:
        quick_test(YOUR_API_KEY)
