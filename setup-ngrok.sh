#!/bin/bash

echo "🌐 Настройка ngrok для внешнего доступа к STVOR Relay"
echo "====================================================="

# Проверка установки ngrok
if ! command -v ngrok &> /dev/null; then
    echo "📦 Установка ngrok..."
    if command -v brew &> /dev/null; then
        brew install ngrok
    else
        echo "❌ Homebrew не найден. Установите ngrok вручную:"
        echo "   https://ngrok.com/download"
        exit 1
    fi
fi

echo "✅ ngrok найден"

# Проверка что сервер работает
if ! curl -s -f http://localhost:3002/health > /dev/null; then
    echo "❌ STVOR Relay сервер не работает на порту 3002"
    echo "   Запустите сначала: ./deploy.sh docker-prod"
    exit 1
fi

echo "✅ STVOR Relay сервер работает на порту 3002"
echo ""
echo "🚀 Создаем публичный туннель..."
echo "   (Нажмите Ctrl+C для остановки)"
echo ""
echo "📋 После запуска:"
echo "   1. Скопируйте HTTPS URL (например: https://abc123.ngrok.io)"
echo "   2. Откройте https://sdk.stvor.xyz/dashboard.html"  
echo "   3. Нажмите F12, в консоли выполните:"
echo "      localStorage.setItem('stvor_relay_url', 'https://ВАШ-NGROK-URL');"
echo "      location.reload();"
echo ""

# Запуск ngrok
ngrok http 3002