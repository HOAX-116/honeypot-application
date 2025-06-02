#!/usr/bin/env python3
"""
Alert Management Service
Monitors honeypot logs and sends alerts for suspicious activity
"""

import os
import logging
import time
import json
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import schedule
import requests
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('alert_service')

class AlertService:
    def __init__(self):
        self.elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'http://elasticsearch:9200')
        self.es = Elasticsearch([self.elasticsearch_host])
        
        # Email configuration
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.alert_email = os.getenv('ALERT_EMAIL')
        
        # Slack configuration
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        
        # Alert thresholds
        self.thresholds = {
            'high_volume_attacks': int(os.getenv('ALERT_THRESHOLD_HIGH_VOLUME', '100')),
            'unique_ips_per_hour': int(os.getenv('ALERT_THRESHOLD_UNIQUE_IPS', '50')),
            'brute_force_attempts': int(os.getenv('ALERT_THRESHOLD_BRUTE_FORCE', '20')),
            'iot_botnet_activity': int(os.getenv('ALERT_THRESHOLD_IOT_BOTNET', '10'))
        }
        
        # Track sent alerts to avoid spam
        self.sent_alerts = {}

    def check_high_volume_attacks(self):
        """Check for high volume of attacks"""
        try:
            # Query for attacks in the last hour
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-1h"}}},
                            {"terms": {"event_type": ["login_attempt", "connection", "command_execution"]}}
                        ]
                    }
                },
                "aggs": {
                    "attack_count": {
                        "value_count": {"field": "event_type"}
                    }
                }
            }
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            attack_count = response['aggregations']['attack_count']['value']
            
            if attack_count > self.thresholds['high_volume_attacks']:
                alert_key = f"high_volume_{datetime.now().strftime('%Y%m%d%H')}"
                if alert_key not in self.sent_alerts:
                    self.send_alert(
                        "High Volume Attack Detected",
                        f"Detected {attack_count} attacks in the last hour (threshold: {self.thresholds['high_volume_attacks']})",
                        "high",
                        {"attack_count": attack_count, "timeframe": "1 hour"}
                    )
                    self.sent_alerts[alert_key] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error checking high volume attacks: {e}")

    def check_unique_ips(self):
        """Check for unusual number of unique IPs"""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-1h"}}},
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
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            unique_ip_count = response['aggregations']['unique_ips']['value']
            
            if unique_ip_count > self.thresholds['unique_ips_per_hour']:
                alert_key = f"unique_ips_{datetime.now().strftime('%Y%m%d%H')}"
                if alert_key not in self.sent_alerts:
                    self.send_alert(
                        "Unusual IP Activity Detected",
                        f"Detected {unique_ip_count} unique IPs in the last hour (threshold: {self.thresholds['unique_ips_per_hour']})",
                        "medium",
                        {"unique_ip_count": unique_ip_count, "timeframe": "1 hour"}
                    )
                    self.sent_alerts[alert_key] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error checking unique IPs: {e}")

    def check_brute_force_attacks(self):
        """Check for brute force attacks from single IPs"""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-1h"}}},
                            {"term": {"event_type": "login_attempt"}}
                        ]
                    }
                },
                "aggs": {
                    "by_ip": {
                        "terms": {
                            "field": "source_ip",
                            "size": 100
                        }
                    }
                }
            }
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            
            for bucket in response['aggregations']['by_ip']['buckets']:
                ip = bucket['key']
                attempt_count = bucket['doc_count']
                
                if attempt_count > self.thresholds['brute_force_attempts']:
                    alert_key = f"brute_force_{ip}_{datetime.now().strftime('%Y%m%d%H')}"
                    if alert_key not in self.sent_alerts:
                        self.send_alert(
                            "Brute Force Attack Detected",
                            f"IP {ip} made {attempt_count} login attempts in the last hour (threshold: {self.thresholds['brute_force_attempts']})",
                            "high",
                            {"source_ip": ip, "attempt_count": attempt_count, "timeframe": "1 hour"}
                        )
                        self.sent_alerts[alert_key] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error checking brute force attacks: {e}")

    def check_iot_botnet_activity(self):
        """Check for IoT botnet activity"""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": "now-1h"}}},
                            {"term": {"attack_type": "iot_botnet"}}
                        ]
                    }
                },
                "aggs": {
                    "iot_count": {
                        "value_count": {"field": "event_type"}
                    },
                    "by_ip": {
                        "terms": {
                            "field": "source_ip",
                            "size": 10
                        }
                    }
                }
            }
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            iot_count = response['aggregations']['iot_count']['value']
            
            if iot_count > self.thresholds['iot_botnet_activity']:
                alert_key = f"iot_botnet_{datetime.now().strftime('%Y%m%d%H')}"
                if alert_key not in self.sent_alerts:
                    top_ips = [bucket['key'] for bucket in response['aggregations']['by_ip']['buckets'][:5]]
                    self.send_alert(
                        "IoT Botnet Activity Detected",
                        f"Detected {iot_count} IoT botnet attempts in the last hour (threshold: {self.thresholds['iot_botnet_activity']})\nTop IPs: {', '.join(top_ips)}",
                        "critical",
                        {"iot_attempt_count": iot_count, "top_ips": top_ips, "timeframe": "1 hour"}
                    )
                    self.sent_alerts[alert_key] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error checking IoT botnet activity: {e}")

    def send_alert(self, subject, message, severity, metadata=None):
        """Send alert via email and Slack"""
        logger.warning(f"ALERT [{severity.upper()}]: {subject} - {message}")
        
        # Send email alert
        if self.alert_email and self.smtp_username and self.smtp_password:
            self.send_email_alert(subject, message, severity, metadata)
        
        # Send Slack alert
        if self.slack_webhook:
            self.send_slack_alert(subject, message, severity, metadata)

    def send_email_alert(self, subject, message, severity, metadata):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = self.alert_email
            msg['Subject'] = f"[HONEYPOT ALERT - {severity.upper()}] {subject}"
            
            # Create email body
            body = f"""
Honeypot Alert - {severity.upper()}

Subject: {subject}
Timestamp: {datetime.utcnow().isoformat()}
Severity: {severity}

Message:
{message}

Metadata:
{json.dumps(metadata, indent=2) if metadata else 'None'}

---
Honeypot Alert System
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent to {self.alert_email}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def send_slack_alert(self, subject, message, severity, metadata):
        """Send Slack alert"""
        try:
            # Color coding for severity
            colors = {
                'low': '#36a64f',      # Green
                'medium': '#ff9500',   # Orange
                'high': '#ff0000',     # Red
                'critical': '#8b0000'  # Dark Red
            }
            
            payload = {
                "attachments": [
                    {
                        "color": colors.get(severity, '#36a64f'),
                        "title": f"Honeypot Alert - {severity.upper()}",
                        "text": subject,
                        "fields": [
                            {
                                "title": "Message",
                                "value": message,
                                "short": False
                            },
                            {
                                "title": "Timestamp",
                                "value": datetime.utcnow().isoformat(),
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": severity.upper(),
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            if metadata:
                payload["attachments"][0]["fields"].append({
                    "title": "Metadata",
                    "value": f"```{json.dumps(metadata, indent=2)}```",
                    "short": False
                })
            
            response = requests.post(self.slack_webhook, json=payload)
            response.raise_for_status()
            
            logger.info("Slack alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    def cleanup_old_alerts(self):
        """Clean up old alert tracking data"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        keys_to_remove = []
        for key, timestamp in self.sent_alerts.items():
            if timestamp < cutoff_time:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.sent_alerts[key]
        
        logger.info(f"Cleaned up {len(keys_to_remove)} old alert records")

    def run_checks(self):
        """Run all alert checks"""
        logger.info("Running alert checks...")
        
        try:
            self.check_high_volume_attacks()
            self.check_unique_ips()
            self.check_brute_force_attacks()
            self.check_iot_botnet_activity()
            
            logger.info("Alert checks completed")
            
        except Exception as e:
            logger.error(f"Error during alert checks: {e}")

    def run(self):
        """Run the alert service"""
        logger.info("Starting alert management service...")
        
        # Schedule alert checks every 5 minutes
        schedule.every(5).minutes.do(self.run_checks)
        
        # Schedule cleanup every hour
        schedule.every().hour.do(self.cleanup_old_alerts)
        
        logger.info("Alert service started. Scheduling checks...")
        
        # Run initial check
        self.run_checks()
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                logger.info("Shutting down alert service...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(60)

def main():
    """Main function"""
    service = AlertService()
    service.run()

if __name__ == '__main__':
    main()