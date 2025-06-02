#!/usr/bin/env python3
"""
GeoIP Enrichment Service
Downloads and maintains MaxMind GeoIP databases
"""

import os
import logging
import time
import gzip
import tarfile
import requests
import schedule
from datetime import datetime
import geoip2.database
from elasticsearch import Elasticsearch

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('geoip_service')

class GeoIPService:
    def __init__(self):
        self.account_id = os.getenv('MAXMIND_ACCOUNT_ID')
        self.license_key = os.getenv('MAXMIND_LICENSE_KEY')
        self.geoip_dir = '/app/geoip'
        self.elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'http://elasticsearch:9200')
        
        # Ensure directories exist
        os.makedirs(self.geoip_dir, exist_ok=True)
        
        # Initialize Elasticsearch client
        self.es = Elasticsearch([self.elasticsearch_host])
        
        # Database files to download
        self.databases = {
            'GeoLite2-City': 'GeoLite2-City.mmdb',
            'GeoLite2-Country': 'GeoLite2-Country.mmdb',
            'GeoLite2-ASN': 'GeoLite2-ASN.mmdb'
        }

    def download_database(self, edition_id):
        """Download GeoIP database from MaxMind"""
        logger.info(f"Downloading {edition_id} database...")
        
        url = f"https://download.maxmind.com/app/geoip_download"
        params = {
            'edition_id': edition_id,
            'license_key': self.license_key,
            'suffix': 'tar.gz'
        }
        
        try:
            response = requests.get(url, params=params, auth=(self.account_id, self.license_key))
            response.raise_for_status()
            
            # Save tar.gz file
            tar_path = os.path.join(self.geoip_dir, f"{edition_id}.tar.gz")
            with open(tar_path, 'wb') as f:
                f.write(response.content)
            
            # Extract database file
            with tarfile.open(tar_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.mmdb'):
                        # Extract to geoip directory with standard name
                        member.name = self.databases[edition_id]
                        tar.extract(member, self.geoip_dir)
                        break
            
            # Clean up tar file
            os.remove(tar_path)
            
            logger.info(f"Successfully downloaded and extracted {edition_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download {edition_id}: {e}")
            return False

    def update_databases(self):
        """Update all GeoIP databases"""
        logger.info("Starting GeoIP database update...")
        
        success_count = 0
        for edition_id in self.databases.keys():
            if self.download_database(edition_id):
                success_count += 1
        
        logger.info(f"Updated {success_count}/{len(self.databases)} databases")
        
        # Update Elasticsearch with database info
        self.update_database_info()

    def update_database_info(self):
        """Update Elasticsearch with database information"""
        try:
            db_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'databases': {},
                'service': 'geoip_updater'
            }
            
            for edition_id, filename in self.databases.items():
                db_path = os.path.join(self.geoip_dir, filename)
                if os.path.exists(db_path):
                    stat = os.stat(db_path)
                    db_info['databases'][edition_id] = {
                        'filename': filename,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'available': True
                    }
                else:
                    db_info['databases'][edition_id] = {
                        'filename': filename,
                        'available': False
                    }
            
            # Index in Elasticsearch
            self.es.index(
                index='honeypot-system',
                body=db_info
            )
            
        except Exception as e:
            logger.error(f"Failed to update database info in Elasticsearch: {e}")

    def test_databases(self):
        """Test GeoIP databases"""
        logger.info("Testing GeoIP databases...")
        
        test_ip = "8.8.8.8"  # Google DNS
        
        for edition_id, filename in self.databases.items():
            db_path = os.path.join(self.geoip_dir, filename)
            
            if not os.path.exists(db_path):
                logger.warning(f"Database {filename} not found")
                continue
            
            try:
                with geoip2.database.Reader(db_path) as reader:
                    if 'City' in edition_id:
                        response = reader.city(test_ip)
                        logger.info(f"{edition_id}: {response.country.name}, {response.city.name}")
                    elif 'Country' in edition_id:
                        response = reader.country(test_ip)
                        logger.info(f"{edition_id}: {response.country.name}")
                    elif 'ASN' in edition_id:
                        response = reader.asn(test_ip)
                        logger.info(f"{edition_id}: AS{response.autonomous_system_number} {response.autonomous_system_organization}")
                        
            except Exception as e:
                logger.error(f"Error testing {edition_id}: {e}")

    def enrich_ip_data(self):
        """Enrich IP data in Elasticsearch with GeoIP information"""
        logger.info("Starting IP data enrichment...")
        
        try:
            # Search for recent logs without GeoIP data
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "source_ip"}},
                            {"range": {"@timestamp": {"gte": "now-1h"}}}
                        ],
                        "must_not": [
                            {"exists": {"field": "geoip.country_name"}}
                        ]
                    }
                },
                "size": 1000
            }
            
            response = self.es.search(index="honeypot-logs-*", body=query)
            
            if response['hits']['total']['value'] == 0:
                logger.info("No IP addresses to enrich")
                return
            
            # Load GeoIP databases
            city_db = None
            asn_db = None
            
            city_path = os.path.join(self.geoip_dir, 'GeoLite2-City.mmdb')
            asn_path = os.path.join(self.geoip_dir, 'GeoLite2-ASN.mmdb')
            
            if os.path.exists(city_path):
                city_db = geoip2.database.Reader(city_path)
            
            if os.path.exists(asn_path):
                asn_db = geoip2.database.Reader(asn_path)
            
            enriched_count = 0
            
            for hit in response['hits']['hits']:
                source_ip = hit['_source'].get('source_ip')
                if not source_ip:
                    continue
                
                geoip_data = {}
                
                # Get city/country data
                if city_db:
                    try:
                        city_response = city_db.city(source_ip)
                        geoip_data.update({
                            'geoip': {
                                'country_name': city_response.country.name,
                                'country_code': city_response.country.iso_code,
                                'city_name': city_response.city.name,
                                'continent_code': city_response.continent.code,
                                'latitude': float(city_response.location.latitude) if city_response.location.latitude else None,
                                'longitude': float(city_response.location.longitude) if city_response.location.longitude else None,
                                'timezone': city_response.location.time_zone
                            }
                        })
                    except Exception as e:
                        logger.debug(f"City lookup failed for {source_ip}: {e}")
                
                # Get ASN data
                if asn_db:
                    try:
                        asn_response = asn_db.asn(source_ip)
                        geoip_data.update({
                            'geoip_asn': {
                                'asn': asn_response.autonomous_system_number,
                                'as_org': asn_response.autonomous_system_organization
                            }
                        })
                    except Exception as e:
                        logger.debug(f"ASN lookup failed for {source_ip}: {e}")
                
                # Update document if we have GeoIP data
                if geoip_data:
                    try:
                        self.es.update(
                            index=hit['_index'],
                            id=hit['_id'],
                            body={'doc': geoip_data}
                        )
                        enriched_count += 1
                    except Exception as e:
                        logger.error(f"Failed to update document {hit['_id']}: {e}")
            
            logger.info(f"Enriched {enriched_count} IP addresses")
            
            # Close databases
            if city_db:
                city_db.close()
            if asn_db:
                asn_db.close()
                
        except Exception as e:
            logger.error(f"Error during IP enrichment: {e}")

    def run(self):
        """Run the GeoIP service"""
        logger.info("Starting GeoIP enrichment service...")
        
        # Initial database download
        self.update_databases()
        self.test_databases()
        
        # Schedule database updates (weekly)
        schedule.every().sunday.at("02:00").do(self.update_databases)
        
        # Schedule IP enrichment (every 5 minutes)
        schedule.every(5).minutes.do(self.enrich_ip_data)
        
        logger.info("GeoIP service started. Scheduling tasks...")
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                logger.info("Shutting down GeoIP service...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(60)

def main():
    """Main function"""
    service = GeoIPService()
    service.run()

if __name__ == '__main__':
    main()