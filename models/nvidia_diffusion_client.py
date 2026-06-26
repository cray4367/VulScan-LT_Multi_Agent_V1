"""
NVIDIA Diffusion model client using direct requests.
Supports chat_template_kwargs (e.g. enable_thinking) and base64 file encoding.
"""

import os
import time
import requests
import base64


def read_b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def create_nvidia_diffusion_client(model_name, temperature=1.0):
    invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"

    def generate(prompt):
        headers = {
            "Authorization": f"Bearer {os.environ['NVIDIA_API_KEY']}",
            "Accept": "application/json",
        }
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
            "temperature": temperature,
            "top_p": 0.95,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": True},
        }
        delay = 0.15
        for attempt in range(5):
            try:
                response = requests.post(
                    invoke_url, headers=headers, json=payload
                )
                response.raise_for_status()
                data = response.json()
                return (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower() or "50" in str(e):
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise RuntimeError("Failed to generate response after 5 rate-limit retries")

    return generate
