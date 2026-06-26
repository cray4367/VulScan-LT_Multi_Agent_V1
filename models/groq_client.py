"""
Groq API client as a simple function.
Returns a 'generate' function that sends prompts to Groq's API.
"""

import os
import time


def create_groq_client(model_name, temperature=0.0):

    import groq

    client = groq.Groq(api_key=os.environ["GROQ_API_KEY"])

    def generate(prompt):
        """Send a prompt to Groq and return the response text."""
        delay = 0.15
        # Retry up to 5 times on rate limits
        for attempt in range(5):
            try:
                resp = client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                )
                return resp.choices[0].message.content or ""
            except Exception as e:
                # If it's a rate limit (429), wait and retry
                if "429" in str(e) or "rate" in str(e).lower():
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        return ""

    return generate
