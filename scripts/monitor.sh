#!/bin/bash
set -e

# Honeypot Monitoring Script
# This script provides monitoring and management capabilities

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Configuration
ELASTICSEARCH_URL="http://localhost:9200"
API_URL="http://localhost:8080"
DOCKER_COMPOSE_FILE="/opt/honeypot/docker-compose.yml"

# Function to check service status
check_service_status() {
    print_header "🔍 Service Status Check"
    echo "======================="
    
    # Check Docker services
    print_status "Checking Docker services..."
    if command -v docker-compose >/dev/null 2>&1; then
        sudo docker-compose -f "$DOCKER_COMPOSE_FILE" ps
    else
        print_warning "docker-compose not found"
    fi
    echo
    
    # Check individual services
    local services=("elasticsearch:9200" "kibana:5601" "logstash:9600" "api-gateway:8080")
    
    for service in "${services[@]}"; do
        IFS=':' read -r name port <<< "$service"
        if nc -z localhost "$port" 2>/dev/null; then
            print_success "$name is running on port $port"
        else
            print_error "$name is not responding on port $port"
        fi
    done
    echo
    
    # Check honeypot services
    local honeypots=("SSH:22" "HTTP:80" "FTP:21" "Telnet:23")
    
    print_status "Checking honeypot services..."
    for honeypot in "${honeypots[@]}"; do
        IFS=':' read -r name port <<< "$honeypot"
        if nc -z localhost "$port" 2>/dev/null; then
            print_success "$name honeypot is active on port $port"
        else
            print_error "$name honeypot is not responding on port $port"
        fi
    done
}

# Function to show system resources
show_system_resources() {
    print_header "💻 System Resources"
    echo "==================="
    
    # CPU usage
    print_status "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4"%"}'
    echo
    
    # Memory usage
    print_status "Memory Usage:"
    free -h
    echo
    
    # Disk usage
    print_status "Disk Usage:"
    df -h | grep -E '^/dev/'
    echo
    
    # Docker container resources
    print_status "Docker Container Resources:"
    if command -v docker >/dev/null 2>&1; then
        sudo docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
    fi
}

# Function to show Elasticsearch health
show_elasticsearch_health() {
    print_header "🔍 Elasticsearch Health"
    echo "======================="
    
    if curl -s "$ELASTICSEARCH_URL" >/dev/null 2>&1; then
        # Cluster health
        print_status "Cluster Health:"
        curl -s "$ELASTICSEARCH_URL/_cluster/health?pretty"
        echo
        
        # Node info
        print_status "Node Information:"
        curl -s "$ELASTICSEARCH_URL/_nodes/stats?pretty" | jq '.nodes | to_entries[0].value | {name: .name, heap_used_percent: .jvm.mem.heap_used_percent, disk_available: .fs.total.available_in_bytes}'
        echo
        
        # Index information
        print_status "Index Information:"
        curl -s "$ELASTICSEARCH_URL/_cat/indices/honeypot-*?v&h=index,health,status,docs.count,store.size"
        echo
        
        # Recent log count
        print_status "Recent Activity (last hour):"
        local recent_count=$(curl -s "$ELASTICSEARCH_URL/honeypot-logs-*/_count?q=@timestamp:[now-1h TO now]" | jq '.count')
        echo "Logs in last hour: $recent_count"
        
    else
        print_error "Elasticsearch is not accessible"
    fi
}

# Function to show attack statistics
show_attack_stats() {
    print_header "🎯 Attack Statistics"
    echo "===================="
    
    if curl -s "$API_URL/health" >/dev/null 2>&1; then
        # Get overview stats
        print_status "Overview (last 24 hours):"
        curl -s "$API_URL/api/stats/overview?hours=24" | jq '{
            total_events: .total_events,
            unique_ips: .unique_ips,
            services: .services,
            attack_types: .attack_types
        }'
        echo
        
        # Top attacking IPs
        print_status "Top 5 Attacking IPs:"
        curl -s "$API_URL/api/stats/top-ips?hours=24&limit=5" | jq '.top_ips[] | {ip: .ip, count: .count, country: .geoip.country}'
        echo
        
        # Country statistics
        print_status "Top 5 Countries:"
        curl -s "$API_URL/api/stats/countries?hours=24" | jq '.countries[:5][] | {country: .country, events: .total_events, unique_ips: .unique_ips}'
        
    else
        print_error "API Gateway is not accessible"
    fi
}

# Function to show recent logs
show_recent_logs() {
    local count="${1:-10}"
    
    print_header "📋 Recent Logs (last $count)"
    echo "========================="
    
    if curl -s "$API_URL/health" >/dev/null 2>&1; then
        curl -s "$API_URL/api/logs/search?size=$count" | jq '.logs[] | {
            timestamp: .timestamp,
            service: .service,
            event_type: .event_type,
            source_ip: .source_ip
        }'
    else
        print_error "API Gateway is not accessible"
    fi
}

# Function to show Docker logs
show_docker_logs() {
    local service="$1"
    local lines="${2:-50}"
    
    print_header "🐳 Docker Logs"
    echo "==============="
    
    if [ -n "$service" ]; then
        print_status "Showing logs for service: $service"
        sudo docker-compose -f "$DOCKER_COMPOSE_FILE" logs --tail="$lines" "$service"
    else
        print_status "Showing logs for all services (last $lines lines each):"
        sudo docker-compose -f "$DOCKER_COMPOSE_FILE" logs --tail="$lines"
    fi
}

# Function to restart services
restart_services() {
    local service="$1"
    
    print_header "🔄 Restarting Services"
    echo "======================"
    
    if [ -n "$service" ]; then
        print_status "Restarting service: $service"
        sudo docker-compose -f "$DOCKER_COMPOSE_FILE" restart "$service"
    else
        print_status "Restarting all services..."
        sudo docker-compose -f "$DOCKER_COMPOSE_FILE" restart
    fi
    
    print_success "Services restarted"
}

# Function to show real-time monitoring
real_time_monitor() {
    print_header "📊 Real-time Monitoring"
    echo "======================="
    print_status "Press Ctrl+C to exit"
    echo
    
    while true; do
        clear
        echo "🍯 Honeypot Real-time Monitor - $(date)"
        echo "========================================"
        echo
        
        # Quick status
        local es_status="❌"
        local api_status="❌"
        
        if curl -s "$ELASTICSEARCH_URL" >/dev/null 2>&1; then
            es_status="✅"
        fi
        
        if curl -s "$API_URL/health" >/dev/null 2>&1; then
            api_status="✅"
        fi
        
        echo "Services: Elasticsearch $es_status | API Gateway $api_status"
        echo
        
        # Recent activity
        if [ "$api_status" = "✅" ]; then
            local recent_count=$(curl -s "$API_URL/api/stats/overview?hours=1" | jq '.total_events // 0')
            local unique_ips=$(curl -s "$API_URL/api/stats/overview?hours=1" | jq '.unique_ips // 0')
            echo "Last hour: $recent_count events from $unique_ips unique IPs"
            echo
            
            # Top services
            echo "Active Services:"
            curl -s "$API_URL/api/stats/overview?hours=1" | jq -r '.services // {} | to_entries[] | "  \(.key): \(.value) events"'
            echo
            
            # Recent attacks
            echo "Recent Attacks:"
            curl -s "$API_URL/api/logs/search?size=5" | jq -r '.logs[]? | "  \(.timestamp[11:19]) \(.service) \(.source_ip) \(.event_type)"'
        fi
        
        echo
        echo "System Resources:"
        echo "  CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4"%"}')"
        echo "  Memory: $(free | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
        echo "  Disk: $(df / | awk 'NR==2{print $5}')"
        
        sleep 5
    done
}

# Function to generate report
generate_report() {
    local hours="${1:-24}"
    local output_file="honeypot_report_$(date +%Y%m%d_%H%M%S).txt"
    
    print_header "📊 Generating Report"
    echo "===================="
    
    {
        echo "Honeypot Security Report"
        echo "========================"
        echo "Generated: $(date)"
        echo "Time Period: Last $hours hours"
        echo
        
        echo "SYSTEM STATUS"
        echo "============="
        check_service_status
        echo
        
        echo "ATTACK STATISTICS"
        echo "================="
        if curl -s "$API_URL/health" >/dev/null 2>&1; then
            curl -s "$API_URL/api/stats/overview?hours=$hours" | jq .
        else
            echo "API Gateway not accessible"
        fi
        echo
        
        echo "TOP ATTACKING IPS"
        echo "================="
        if curl -s "$API_URL/health" >/dev/null 2>&1; then
            curl -s "$API_URL/api/stats/top-ips?hours=$hours&limit=10" | jq .
        else
            echo "API Gateway not accessible"
        fi
        echo
        
        echo "SYSTEM RESOURCES"
        echo "================"
        show_system_resources
        
    } > "$output_file"
    
    print_success "Report generated: $output_file"
}

# Function to show help
show_help() {
    echo "🍯 Honeypot Monitoring Script"
    echo "============================="
    echo
    echo "Usage: $0 [command] [options]"
    echo
    echo "Commands:"
    echo "  status              - Show service status"
    echo "  resources           - Show system resources"
    echo "  elasticsearch       - Show Elasticsearch health"
    echo "  stats               - Show attack statistics"
    echo "  logs [count]        - Show recent logs (default: 10)"
    echo "  docker-logs [service] [lines] - Show Docker logs"
    echo "  restart [service]   - Restart services"
    echo "  monitor             - Real-time monitoring"
    echo "  report [hours]      - Generate report (default: 24 hours)"
    echo "  help                - Show this help"
    echo
    echo "Examples:"
    echo "  $0 status           - Check all service status"
    echo "  $0 logs 20          - Show last 20 log entries"
    echo "  $0 docker-logs ssh-honeypot 100 - Show 100 lines of SSH honeypot logs"
    echo "  $0 restart elasticsearch - Restart Elasticsearch service"
    echo "  $0 report 48        - Generate 48-hour report"
    echo
}

# Main function
main() {
    local command="${1:-status}"
    
    case $command in
        "status")
            check_service_status
            ;;
        "resources")
            show_system_resources
            ;;
        "elasticsearch"|"es")
            show_elasticsearch_health
            ;;
        "stats")
            show_attack_stats
            ;;
        "logs")
            show_recent_logs "$2"
            ;;
        "docker-logs")
            show_docker_logs "$2" "$3"
            ;;
        "restart")
            restart_services "$2"
            ;;
        "monitor")
            real_time_monitor
            ;;
        "report")
            generate_report "$2"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Check if jq is available
if ! command -v jq >/dev/null 2>&1; then
    print_warning "jq is not installed. Some features may not work properly."
    print_status "Install jq with: sudo apt-get install jq"
fi

# Run main function
main "$@"