#!/usr/bin/env python3
"""
Health Monitoring Service
Monitors the health of all honeypot services and infrastructure
"""

import os
import logging
import time
import json
from datetime import datetime
import requests
import schedule
from elasticsearch import Elasticsearch
import docker

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('health_monitor')

class HealthMonitor:
    def __init__(self):
        self.elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'http://elasticsearch:9200')
        self.es = Elasticsearch([self.elasticsearch_host])
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Could not initialize Docker client: {e}")
            self.docker_client = None
        
        # Services to monitor
        self.services = {
            'elasticsearch': {'url': 'http://elasticsearch:9200/_cluster/health', 'type': 'elasticsearch'},
            'kibana': {'url': 'http://kibana:5601/api/status', 'type': 'kibana'},
            'logstash': {'url': 'http://logstash:9600/_node/stats', 'type': 'logstash'},
            'api_gateway': {'url': 'http://api-gateway:8080/health', 'type': 'api'},
            'ssh_honeypot': {'port': 22, 'type': 'honeypot'},
            'http_honeypot': {'port': 80, 'type': 'honeypot'},
            'ftp_honeypot': {'port': 21, 'type': 'honeypot'},
            'telnet_honeypot': {'port': 23, 'type': 'honeypot'}
        }

    def check_service_health(self, service_name, config):
        """Check health of a specific service"""
        try:
            if 'url' in config:
                # HTTP health check
                response = requests.get(config['url'], timeout=10)
                if response.status_code == 200:
                    return {'status': 'healthy', 'response_time': response.elapsed.total_seconds()}
                else:
                    return {'status': 'unhealthy', 'error': f"HTTP {response.status_code}"}
            
            elif 'port' in config:
                # Port connectivity check
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((service_name.replace('_', '-'), config['port']))
                sock.close()
                
                if result == 0:
                    return {'status': 'healthy', 'port': config['port']}
                else:
                    return {'status': 'unhealthy', 'error': f"Port {config['port']} not accessible"}
            
            else:
                return {'status': 'unknown', 'error': 'No health check method configured'}
                
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}

    def check_docker_containers(self):
        """Check Docker container health"""
        container_health = {}
        
        if not self.docker_client:
            return container_health
        
        try:
            containers = self.docker_client.containers.list(all=True)
            
            for container in containers:
                name = container.name
                status = container.status
                
                # Get container stats if running
                stats = {}
                if status == 'running':
                    try:
                        container_stats = container.stats(stream=False)
                        
                        # Calculate CPU usage
                        cpu_delta = container_stats['cpu_stats']['cpu_usage']['total_usage'] - \
                                   container_stats['precpu_stats']['cpu_usage']['total_usage']
                        system_delta = container_stats['cpu_stats']['system_cpu_usage'] - \
                                      container_stats['precpu_stats']['system_cpu_usage']
                        
                        if system_delta > 0:
                            cpu_percent = (cpu_delta / system_delta) * 100.0
                        else:
                            cpu_percent = 0.0
                        
                        # Calculate memory usage
                        memory_usage = container_stats['memory_stats']['usage']
                        memory_limit = container_stats['memory_stats']['limit']
                        memory_percent = (memory_usage / memory_limit) * 100.0
                        
                        stats = {
                            'cpu_percent': round(cpu_percent, 2),
                            'memory_usage_mb': round(memory_usage / 1024 / 1024, 2),
                            'memory_percent': round(memory_percent, 2)
                        }
                        
                    except Exception as e:
                        logger.debug(f"Could not get stats for {name}: {e}")
                
                container_health[name] = {
                    'status': status,
                    'image': container.image.tags[0] if container.image.tags else 'unknown',
                    'stats': stats
                }
                
        except Exception as e:
            logger.error(f"Error checking Docker containers: {e}")
        
        return container_health

    def check_elasticsearch_indices(self):
        """Check Elasticsearch indices health"""
        try:
            # Get index health
            indices_health = self.es.cat.indices(index="honeypot-*", format="json")
            
            index_info = {}
            for index in indices_health:
                index_info[index['index']] = {
                    'health': index['health'],
                    'status': index['status'],
                    'docs_count': int(index['docs.count']) if index['docs.count'] != 'null' else 0,
                    'store_size': index['store.size']
                }
            
            return index_info
            
        except Exception as e:
            logger.error(f"Error checking Elasticsearch indices: {e}")
            return {}

    def check_log_ingestion_rate(self):
        """Check log ingestion rate"""
        try:
            # Check logs from last 5 minutes
            query = {
                "query": {
                    "range": {"@timestamp": {"gte": "now-5m"}}
                },
                "aggs": {
                    "by_service": {
                        "terms": {"field": "service", "size": 10}
                    }
                }
            }
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            
            total_logs = response['hits']['total']['value']
            logs_per_minute = total_logs / 5
            
            service_rates = {}
            for bucket in response['aggregations']['by_service']['buckets']:
                service_rates[bucket['key']] = bucket['doc_count'] / 5
            
            return {
                'total_logs_5min': total_logs,
                'logs_per_minute': round(logs_per_minute, 2),
                'service_rates': service_rates
            }
            
        except Exception as e:
            logger.error(f"Error checking log ingestion rate: {e}")
            return {}

    def run_health_checks(self):
        """Run all health checks"""
        logger.info("Running health checks...")
        
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'services': {},
            'containers': {},
            'elasticsearch_indices': {},
            'log_ingestion': {},
            'overall_status': 'healthy'
        }
        
        # Check services
        unhealthy_services = 0
        for service_name, config in self.services.items():
            health = self.check_service_health(service_name, config)
            health_report['services'][service_name] = health
            
            if health['status'] != 'healthy':
                unhealthy_services += 1
                logger.warning(f"Service {service_name} is unhealthy: {health.get('error', 'Unknown error')}")
        
        # Check Docker containers
        health_report['containers'] = self.check_docker_containers()
        
        # Check Elasticsearch indices
        health_report['elasticsearch_indices'] = self.check_elasticsearch_indices()
        
        # Check log ingestion
        health_report['log_ingestion'] = self.check_log_ingestion_rate()
        
        # Determine overall status
        if unhealthy_services > 0:
            if unhealthy_services >= len(self.services) / 2:
                health_report['overall_status'] = 'critical'
            else:
                health_report['overall_status'] = 'degraded'
        
        # Log health report to Elasticsearch
        try:
            self.es.index(
                index='honeypot-health',
                body=health_report
            )
        except Exception as e:
            logger.error(f"Failed to log health report to Elasticsearch: {e}")
        
        # Log summary
        healthy_count = len(self.services) - unhealthy_services
        logger.info(f"Health check completed: {healthy_count}/{len(self.services)} services healthy, "
                   f"overall status: {health_report['overall_status']}")
        
        return health_report

    def check_disk_space(self):
        """Check disk space usage"""
        try:
            import shutil
            
            # Check root filesystem
            total, used, free = shutil.disk_usage('/')
            
            disk_info = {
                'total_gb': round(total / (1024**3), 2),
                'used_gb': round(used / (1024**3), 2),
                'free_gb': round(free / (1024**3), 2),
                'used_percent': round((used / total) * 100, 2)
            }
            
            # Log warning if disk usage is high
            if disk_info['used_percent'] > 80:
                logger.warning(f"High disk usage: {disk_info['used_percent']}%")
            
            return disk_info
            
        except Exception as e:
            logger.error(f"Error checking disk space: {e}")
            return {}

    def cleanup_old_health_data(self):
        """Clean up old health monitoring data"""
        try:
            # Delete health data older than 7 days
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "lt": "now-7d"
                        }
                    }
                }
            }
            
            result = self.es.delete_by_query(
                index="honeypot-health",
                body=query
            )
            
            deleted_count = result.get('deleted', 0)
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old health records")
            
        except Exception as e:
            logger.error(f"Error cleaning up old health data: {e}")

    def run(self):
        """Run the health monitoring service"""
        logger.info("Starting health monitoring service...")
        
        # Schedule health checks every 2 minutes
        schedule.every(2).minutes.do(self.run_health_checks)
        
        # Schedule cleanup every day
        schedule.every().day.at("03:00").do(self.cleanup_old_health_data)
        
        logger.info("Health monitoring service started. Scheduling checks...")
        
        # Run initial health check
        self.run_health_checks()
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(30)  # Check every 30 seconds
            except KeyboardInterrupt:
                logger.info("Shutting down health monitoring service...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(30)

def main():
    """Main function"""
    monitor = HealthMonitor()
    monitor.run()

if __name__ == '__main__':
    main()