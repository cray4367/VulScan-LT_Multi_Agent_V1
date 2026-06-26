"""
NVIDIA API client as a simple function.
Returns a 'generate' function that sends prompts to NVIDIA's API.
"""

import os
import time


def create_nvidia_client(model_name, temperature=0.0):

    from openai import OpenAI

    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"],
    )

    def generate(prompt):
        """Send a prompt to NVIDIA and return the response text."""
        delay = 0.15
        for attempt in range(5):
            try:
                # NVIDIA uses streaming, so we collect chunks
                resp = client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    max_tokens=16384,
                    stream=True,
                )
                content = ""
                for chunk in resp:
                    if not getattr(chunk, "choices", None):
                        continue
                    if len(chunk.choices) == 0 or getattr(chunk.choices[0], "delta", None) is None:
                        continue
                    delta = chunk.choices[0].delta
                    if getattr(delta, "content", None) is not None:
                        content += delta.content
                return content
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower() or "50" in str(e):
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise RuntimeError("Failed to generate response after 5 rate-limit retries")

    return generate
