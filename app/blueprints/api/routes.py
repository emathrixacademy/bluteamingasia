from flask import request, jsonify
from app.blueprints.api import api_bp
from app.blueprints.api.auth import api_key_required
from app.services.event_service import process_event
from app.services.vector_search_service import find_similar_events, search_knowledge_base


@api_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'platform': 'BlueteamingAsia'})


@api_bp.route('/events', methods=['POST'])
@api_key_required
def ingest_event():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON body provided'}), 400
    result = process_event(data)
    status_code = 201 if result['status'] == 'processed' else 400
    return jsonify(result), status_code


@api_bp.route('/events/<event_id>/similar', methods=['GET'])
@api_key_required
def similar_events(event_id):
    limit = request.args.get('limit', 10, type=int)
    results = find_similar_events(event_id, limit=limit)
    return jsonify({
        'event_id': event_id,
        'similar_events': [
            {
                'event_id': str(r['event'].id),
                'event_type': r['event'].event_type,
                'severity': r['event'].severity,
                'similarity': round(r['similarity'], 4),
                'timestamp': r['event'].timestamp.isoformat(),
            }
            for r in results
        ]
    })


@api_bp.route('/knowledge/search', methods=['GET'])
@api_key_required
def knowledge_search():
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query parameter q is required'}), 400
    limit = request.args.get('limit', 5, type=int)
    results = search_knowledge_base(query, limit=limit)
    return jsonify({
        'query': query,
        'results': [
            {
                'id': str(r['document'].id),
                'title': r['document'].title,
                'content': r['document'].content[:500],
                'doc_type': r['document'].doc_type,
                'similarity': round(r['similarity'], 4),
            }
            for r in results
        ]
    })
