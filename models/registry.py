"""
Model registry - maps human-readable names to model 'generate' functions.

Each entry is either:
- (factory_function, model_name) for a single provider
- (create_auto_client, [list of (factory, model_name)]) for auto-fallback
"""

from models.auto_client import create_auto_client
from models.groq_client import create_groq_client
from models.lm_studio_client import create_lm_studio_client
from models.openrouter_client import create_openrouter_client
from models.nvidia_client import create_nvidia_client
from models.nvidia_diffusion_client import create_nvidia_diffusion_client


MODEL_REGISTRY = {
    # --- LM Studio (local) ---
    "local-gpt-oss-20b":       (create_lm_studio_client, "gpt-oss-20b"),
    # --- Groq ---
    "groq-gpt-oss-20b":        (create_groq_client, "openai/gpt-oss-20b"),
    "groq-gpt-oss-120b":       (create_groq_client, "openai/gpt-oss-120b"),
    # --- OpenRouter ---
    "openrouter-gpt-oss-20b":  (create_openrouter_client, "openai/gpt-oss-20b"),
    "openrouter-gpt-oss-120b": (create_openrouter_client, "openai/gpt-oss-120b"),
    # --- NVIDIA ---
    "nvidia-gpt-oss-20b":              (create_nvidia_client, "openai/gpt-oss-20b"),
    "nvidia-gpt-oss-120b":             (create_nvidia_client, "openai/gpt-oss-120b"),
    "nvidia-diffusiongemma-26b":       (create_nvidia_diffusion_client, "google/diffusiongemma-26b-a4b-it"),

    # --- Auto Fallback (tries Groq -> OpenRouter -> NVIDIA on failure) ---
    "auto-gpt-oss-20b": (create_auto_client, [
        (create_groq_client, "openai/gpt-oss-20b"),
        (create_openrouter_client, "openai/gpt-oss-20b"),
        (create_nvidia_client, "openai/gpt-oss-20b"),
    ]),
    "auto-gpt-oss-120b": (create_auto_client, [
        (create_groq_client, "openai/gpt-oss-120b"),
        (create_openrouter_client, "openai/gpt-oss-120b"),
        (create_nvidia_client, "openai/gpt-oss-120b"),
    ]),
}


def get_model(model_key, temperature=0.0):

    if model_key not in MODEL_REGISTRY:
        raise ValueError(
            f"Unknown model '{model_key}'. Available: {list(MODEL_REGISTRY.keys())}"
        )

    entry = MODEL_REGISTRY[model_key]
    factory_fn, arg = entry

    # If the factory is create_auto_client, arg is a list of providers
    if factory_fn is create_auto_client:
        return factory_fn(arg, temperature=temperature)

    # Otherwise arg is just a model name string
    return factory_fn(arg, temperature=temperature)
