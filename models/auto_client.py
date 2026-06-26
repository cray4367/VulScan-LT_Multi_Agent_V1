"""
Auto-fallback model client.
Tries multiple API providers in sequence - if one fails, it falls back to the next.
"""


def create_auto_client(providers, temperature=0.0):
    def generate(prompt):
        """Try each provider in order until one works."""
        last_error = None
        for provider_factory, model_name in providers:
            # Create a generate function for this provider
            generate_fn = provider_factory(model_name, temperature=temperature)
            try:
                result = generate_fn(prompt)
                if result:
                    return result
                last_error = RuntimeError(f"{provider_factory.__name__}({model_name}): empty response")
            except Exception as e:
                last_error = e
        raise RuntimeError("All fallback providers exhausted") from last_error

    return generate
