"""
LM Studio local client as a simple function.
Returns a 'generate' function that sends prompts to a local LM Studio server.
"""

import os


def create_lm_studio_client(model_name, temperature=0.0):

    from openai import OpenAI

    base_url = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
    client = OpenAI(base_url=base_url, api_key="lm-studio")

    def generate(prompt):
        """Send a prompt to local LM Studio and return the response text."""
        resp = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=2048,
        )
        return resp.choices[0].message.content or ""

    return generate
