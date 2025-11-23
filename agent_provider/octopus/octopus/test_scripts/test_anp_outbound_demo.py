"""
ANP 出站通道最小演示脚本

作用：
- 使用 ANPClient 通过 ANP Gateway 访问一个目标 URL
- 在日志中可看到 `ANP request: <gateway_url> (original: <target>)` 的记录，证明经由网关转发

准备：
- 确保 .env 或实例 .env 中配置了：
  - ANP_GATEWAY_HTTP_URL 或 ANP_GATEWAY_WS_URL
  - did_document_path、did_private_key_path（可选，但用于签名更完整）
- 目标 URL 建议为本机另一个实例的地址，或任意可访问的 HTTP 资源；若是本机 127.0.0.1，部分场景会走直连优化，建议改为实际 IP 或自定义域名
"""

import asyncio
import os

from octopus.anp_sdk.anp_crawler.anp_client import ANPClient
from octopus.config.settings import get_settings


async def main():
    settings = get_settings()

    # 目标 URL（示例：访问 B 实例的 ad.json）
    # 推荐用主机名以命中网关的 vhost 映射（例如 hosts 配置了 octopus-b.local -> 127.0.0.1）
    # 你也可以换成其他地址，例如 http://your-host:9529/ad.json
    target_url = os.getenv("ANP_DEMO_TARGET", "http://octopus-b.local:9529/ad.json")

    # DID 路径（可从 .env 读取；如果没有，也可以先跑通无签名的路径）
    did_doc = settings.did_document_path or "docs/user_public/did.json"
    priv_key = settings.did_private_key_path or "docs/jwt_key/private_key.pem"

    # 网关 HTTP 入口（优先用 ANP_GATEWAY_HTTP_URL，没有则由 WS URL 推导）
    gateway_http = settings.anp_gateway_http_url or settings.anp_gateway_ws_url

    print("\n==== ANP Outbound Demo ====")
    print(f"Target URL      : {target_url}")
    print(f"DID Document    : {did_doc}")
    print(f"Private Key     : {priv_key}")
    print(f"Gateway (conf)  : {gateway_http}")

    client = ANPClient(
        did_document_path=str(did_doc),
        private_key_path=str(priv_key),
        gateway_url=None,  # 走默认配置推导
    )

    result = await client.fetch_url(target_url, method="GET")
    print("\n---- Result ----")
    print({k: result.get(k) for k in ["success", "status_code", "content_type", "url"]})
    if not result.get("success"):
        print("error:", result.get("error"))
    else:
        print("payload sample:", (result.get("text") or "")[:200])


if __name__ == "__main__":
    asyncio.run(main())
