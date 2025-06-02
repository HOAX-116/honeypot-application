#!/usr/bin/env python3
"""
API Gateway Service
Provides REST API for honeypot data and statistics
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('api_gateway')

# Create Flask app
app = Flask(__name__)
CORS(app)

# Initialize Elasticsearch
elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'http://elasticsearch:9200')
es = Elasticsearch([elasticsearch_host])

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check Elasticsearch connection
        es.ping()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'api_gateway'
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'api_gateway'
        }), 500

@app.route('/api/stats/overview', methods=['GET'])
def get_overview_stats():
    """Get overview statistics"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        time_range = f"now-{hours}h"
        
        # Total events
        total_query = {
            "query": {
                "range": {"@timestamp": {"gte": time_range}}
            }
        }
        total_response = es.count(index="honeypot-logs-*", body=total_query)
        total_events = total_response['count']
        
        # Unique IPs
        unique_ips_query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range}}},
                        {"exists": {"field": "source_ip"}}
                    ]
                }
            },
            "aggs": {
                "unique_ips": {
                    "cardinality": {"field": "source_ip"}
                }
            }
        }
        unique_ips_response = es.search(index="honeypot-logs-*", body=unique_ips_query)
        unique_ips = unique_ips_response['aggregations']['unique_ips']['value']
        
        # Events by service
        services_query = {
            "query": {
                "range": {"@timestamp": {"gte": time_range}}
            },
            "aggs": {
                "by_service": {
                    "terms": {"field": "service", "size": 10}
                }
            }
        }
        services_response = es.search(index="honeypot-logs-*", body=services_query)
        services = {bucket['key']: bucket['doc_count'] for bucket in services_response['aggregations']['by_service']['buckets']}
        
        # Attack types
        attacks_query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range}}},
                        {"exists": {"field": "attack_type"}}
                    ]
                }
            },
            "aggs": {
                "by_attack_type": {
                    "terms": {"field": "attack_type", "size": 10}
                }
            }
        }
        attacks_response = es.search(index="honeypot-logs-*", body=attacks_query)
        attack_types = {bucket['key']: bucket['doc_count'] for bucket in attacks_response['aggregations']['by_attack_type']['buckets']}
        
        return jsonify({
            'timeframe': f"{hours} hours",
            'total_events': total_events,
            'unique_ips': unique_ips,
            'services': services,
            'attack_types': attack_types,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting overview stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/timeline', methods=['GET'])
def get_timeline_stats():
    """Get timeline statistics"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        interval = request.args.get('interval', '1h')
        time_range = f"now-{hours}h"
        
        query = {
            "query": {
                "range": {"@timestamp": {"gte": time_range}}
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0
                    },
                    "aggs": {
                        "by_service": {
                            "terms": {"field": "service", "size": 10}
                        }
                    }
                }
            }
        }
        
        response = es.search(index="honeypot-logs-*", body=query)
        
        timeline_data = []
        for bucket in response['aggregations']['timeline']['buckets']:
            timestamp = bucket['key_as_string']
            total_count = bucket['doc_count']
            services = {service_bucket['key']: service_bucket['doc_count'] 
                       for service_bucket in bucket['by_service']['buckets']}
            
            timeline_data.append({
                'timestamp': timestamp,
                'total': total_count,
                'services': services
            })
        
        return jsonify({
            'timeframe': f"{hours} hours",
            'interval': interval,
            'timeline': timeline_data,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting timeline stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/top-ips', methods=['GET'])
def get_top_ips():
    """Get top attacking IPs"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 10))
        time_range = f"now-{hours}h"
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range}}},
                        {"exists": {"field": "source_ip"}}
                    ]
                }
            },
            "aggs": {
                "top_ips": {
                    "terms": {
                        "field": "source_ip",
                        "size": limit
                    },
                    "aggs": {
                        "by_service": {
                            "terms": {"field": "service", "size": 5}
                        },
                        "by_attack_type": {
                            "terms": {"field": "attack_type", "size": 5}
                        },
                        "geoip_info": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["geoip.country_name", "geoip.city_name", "geoip_asn.as_org"]
                            }
                        }
                    }
                }
            }
        }
        
        response = es.search(index="honeypot-logs-*", body=query)
        
        top_ips = []
        for bucket in response['aggregations']['top_ips']['buckets']:
            ip = bucket['key']
            count = bucket['doc_count']
            
            services = {service_bucket['key']: service_bucket['doc_count'] 
                       for service_bucket in bucket['by_service']['buckets']}
            
            attack_types = {attack_bucket['key']: attack_bucket['doc_count'] 
                           for attack_bucket in bucket['by_attack_type']['buckets']}
            
            # Get GeoIP info
            geoip_info = {}
            if bucket['geoip_info']['hits']['hits']:
                source = bucket['geoip_info']['hits']['hits'][0]['_source']
                if 'geoip' in source:
                    geoip_info = {
                        'country': source['geoip'].get('country_name'),
                        'city': source['geoip'].get('city_name')
                    }
                if 'geoip_asn' in source:
                    geoip_info['as_org'] = source['geoip_asn'].get('as_org')
            
            top_ips.append({
                'ip': ip,
                'count': count,
                'services': services,
                'attack_types': attack_types,
                'geoip': geoip_info
            })
        
        return jsonify({
            'timeframe': f"{hours} hours",
            'top_ips': top_ips,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting top IPs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/countries', methods=['GET'])
def get_country_stats():
    """Get attack statistics by country"""
    try:
        # Get time range from query params
        hours = int(request.args.get('hours', 24))
        time_range = f"now-{hours}h"
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range}}},
                        {"exists": {"field": "geoip.country_name"}}
                    ]
                }
            },
            "aggs": {
                "by_country": {
                    "terms": {
                        "field": "geoip.country_name",
                        "size": 20
                    },
                    "aggs": {
                        "unique_ips": {
                            "cardinality": {"field": "source_ip"}
                        }
                    }
                }
            }
        }
        
        response = es.search(index="honeypot-logs-*", body=query)
        
        countries = []
        for bucket in response['aggregations']['by_country']['buckets']:
            countries.append({
                'country': bucket['key'],
                'total_events': bucket['doc_count'],
                'unique_ips': bucket['unique_ips']['value']
            })
        
        return jsonify({
            'timeframe': f"{hours} hours",
            'countries': countries,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting country stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/search', methods=['GET'])
def search_logs():
    """Search honeypot logs"""
    try:
        # Get search parameters
        query_string = request.args.get('q', '*')
        hours = int(request.args.get('hours', 24))
        size = int(request.args.get('size', 100))
        from_param = int(request.args.get('from', 0))
        service = request.args.get('service')
        source_ip = request.args.get('source_ip')
        
        time_range = f"now-{hours}h"
        
        # Build query
        must_clauses = [
            {"range": {"@timestamp": {"gte": time_range}}}
        ]
        
        if query_string != '*':
            must_clauses.append({
                "query_string": {"query": query_string}
            })
        
        if service:
            must_clauses.append({"term": {"service": service}})
        
        if source_ip:
            must_clauses.append({"term": {"source_ip": source_ip}})
        
        query = {
            "query": {
                "bool": {"must": must_clauses}
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": from_param,
            "size": size
        }
        
        response = es.search(index="honeypot-logs-*", body=query)
        
        logs = []
        for hit in response['hits']['hits']:
            logs.append({
                'id': hit['_id'],
                'timestamp': hit['_source'].get('@timestamp'),
                'service': hit['_source'].get('service'),
                'event_type': hit['_source'].get('event_type'),
                'source_ip': hit['_source'].get('source_ip'),
                'data': hit['_source']
            })
        
        return jsonify({
            'total': response['hits']['total']['value'],
            'logs': logs,
            'query': query_string,
            'timeframe': f"{hours} hours",
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    """Get system status"""
    try:
        # Check Elasticsearch cluster health
        cluster_health = es.cluster.health()
        
        # Get index information
        indices_stats = es.indices.stats(index="honeypot-logs-*")
        
        # Calculate storage usage
        total_size = 0
        total_docs = 0
        
        for index_name, index_stats in indices_stats['indices'].items():
            total_size += index_stats['total']['store']['size_in_bytes']
            total_docs += index_stats['total']['docs']['count']
        
        return jsonify({
            'elasticsearch': {
                'status': cluster_health['status'],
                'number_of_nodes': cluster_health['number_of_nodes'],
                'active_primary_shards': cluster_health['active_primary_shards']
            },
            'storage': {
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / 1024 / 1024, 2),
                'total_documents': total_docs
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting API Gateway on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)