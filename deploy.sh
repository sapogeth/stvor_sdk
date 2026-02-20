#!/bin/bash

# STVOR Production Deployment Script

set -e

echo "🚀 STVOR Server Deployment & Management"
echo "============================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

function print_error() {
    echo -e "${RED}✗${NC} $1"
}

case "$1" in
    docker)
        echo "📦 Starting with Docker..."
        docker-compose down
        docker-compose build
        docker-compose up -d
        print_status "STVOR API running in Docker"
        echo "API: http://localhost:3001"
        echo "Relay: http://localhost:3002"
        ;;
        
    docker-prod)
        echo "🏭 Starting production with Docker..."
        docker-compose -f docker-compose.prod.yml down
        docker-compose -f docker-compose.prod.yml build
        docker-compose -f docker-compose.prod.yml up -d
        print_status "STVOR API running in production mode"
        echo "API: http://localhost:3001"
        echo "Relay: http://localhost:3002"
        echo "WebSocket: ws://localhost:8080"
        echo "Nginx: http://localhost:80"
        ;;
        
    pm2)
        echo "⚡ Starting with PM2..."
        
        # Check if PM2 is installed
        if ! command -v pm2 &> /dev/null; then
            echo "Installing PM2..."
            npm install -g pm2
        fi
        
        # Build project
        npm run build
        
        # Start services
        pm2 start ecosystem.config.js
        pm2 save
        pm2 startup
        
        print_status "STVOR services started with PM2"
        pm2 status
        ;;
        
    systemd)
        echo "🔧 Setting up systemd services..."
        
        # Build project
        npm run build
        
        # Copy service files
        sudo cp stvor-api.service /etc/systemd/system/
        sudo cp stvor-ws-relay.service /etc/systemd/system/
        
        # Reload and enable services
        sudo systemctl daemon-reload
        sudo systemctl enable stvor-api
        sudo systemctl enable stvor-ws-relay
        
        # Start services
        sudo systemctl start stvor-api
        sudo systemctl start stvor-ws-relay
        
        print_status "STVOR services installed and started"
        sudo systemctl status stvor-api
        sudo systemctl status stvor-ws-relay
        ;;
        
    status)
        echo "📊 Service Status"
        echo "=================="
        
        if command -v docker &> /dev/null && docker-compose ps | grep -q "Up"; then
            print_status "Docker: Running"
            docker-compose ps
        fi
        
        if command -v pm2 &> /dev/null; then
            echo ""
            pm2 status
        fi
        
        if systemctl is-active --quiet stvor-api; then
            print_status "Systemd: stvor-api running"
        else
            print_warning "Systemd: stvor-api not running"
        fi
        
        if systemctl is-active --quiet stvor-ws-relay; then
            print_status "Systemd: stvor-ws-relay running"
        else
            print_warning "Systemd: stvor-ws-relay not running"
        fi
        ;;
        
    logs)
        case "$2" in
            docker)
                docker-compose logs -f
                ;;
            pm2)
                pm2 logs
                ;;
            systemd)
                journalctl -f -u stvor-api -u stvor-ws-relay
                ;;
            *)
                echo "Usage: $0 logs [docker|pm2|systemd]"
                ;;
        esac
        ;;
        
    stop)
        echo "🛑 Stopping services..."
        
        # Stop Docker
        if command -v docker-compose &> /dev/null; then
            docker-compose down
        fi
        
        # Stop PM2
        if command -v pm2 &> /dev/null; then
            pm2 stop all
            pm2 delete all
        fi
        
        # Stop systemd
        if systemctl is-active --quiet stvor-api; then
            sudo systemctl stop stvor-api stvor-ws-relay
        fi
        
        print_status "All services stopped"
        ;;
        
    *)
        echo "STVOR Server Management"
        echo "======================"
        echo ""
        echo "Usage: $0 {docker|docker-prod|pm2|systemd|status|logs|stop}"
        echo ""
        echo "Commands:"
        echo "  docker       - Run with Docker Compose (development)"
        echo "  docker-prod  - Run with Docker Compose (production)"
        echo "  pm2          - Run with PM2 process manager"
        echo "  systemd      - Run as system service"
        echo "  status       - Show service status"
        echo "  logs         - View logs (specify: docker|pm2|systemd)"
        echo "  stop         - Stop all services"
        echo ""
        echo "Examples:"
        echo "  $0 docker-prod       # Start production stack"
        echo "  $0 docker            # Start development"
        echo "  $0 pm2               # Start with PM2"
        echo "  $0 logs docker       # View Docker logs"
        echo "  $0 status            # Check all services"
        exit 1
        ;;
esac