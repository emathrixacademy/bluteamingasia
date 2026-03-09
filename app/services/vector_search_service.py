from app.extensions import db
from app.models.event import Event
from app.models.knowledge import KnowledgeDocument
from app.services.embedding_service import generate_embedding


def find_similar_events(event_id, limit=10):
    """Find events similar to a given event using cosine similarity."""
    source_event = Event.query.get(event_id)
    if not source_event or source_event.embedding is None:
        return []

    try:
        results = (
            db.session.query(
                Event,
                Event.embedding.cosine_distance(source_event.embedding).label('distance')
            )
            .filter(Event.id != source_event.id)
            .filter(Event.embedding.isnot(None))
            .order_by('distance')
            .limit(limit)
            .all()
        )
        return [{'event': r[0], 'similarity': round(1 - r[1], 4)} for r in results]
    except Exception:
        return []


def search_knowledge_base(query_text, limit=5):
    """Semantic search over knowledge base documents."""
    query_embedding = generate_embedding(query_text)
    if query_embedding is None:
        return []

    try:
        results = (
            db.session.query(
                KnowledgeDocument,
                KnowledgeDocument.embedding.cosine_distance(query_embedding).label('distance')
            )
            .filter(KnowledgeDocument.embedding.isnot(None))
            .order_by('distance')
            .limit(limit)
            .all()
        )
        return [{'document': r[0], 'similarity': round(1 - r[1], 4)} for r in results]
    except Exception:
        return []
