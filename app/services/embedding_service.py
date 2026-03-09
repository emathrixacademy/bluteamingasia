from flask import current_app

_model = None


def get_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            model_name = current_app.config.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2')
            _model = SentenceTransformer(model_name)
        except ImportError:
            _model = None
    return _model


def generate_embedding(text):
    """Generate a vector embedding from text. Returns None if model unavailable."""
    model = get_model()
    if model is None:
        return None
    embedding = model.encode(text, normalize_embeddings=True)
    return embedding.tolist()


def generate_event_text(event_data):
    """Convert an event's structured data into text for embedding."""
    parts = [
        f"Event type: {event_data.get('event_type', 'unknown')}",
        f"Severity: {event_data.get('severity', 'unknown')}",
        f"Device type: {event_data.get('device_type', 'unknown')}",
        f"Location: {event_data.get('location', 'unknown')}",
    ]
    data = event_data.get('data', {})
    if isinstance(data, dict):
        for k, v in data.items():
            parts.append(f"{k}: {v}")
    return ". ".join(parts)
