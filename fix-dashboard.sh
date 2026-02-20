#!/bin/bash

echo "🔧 STVOR Dashboard Quick Fix"
echo "============================="

echo ""
echo "Проблема: Онлайн дашборд https://sdk.stvor.xyz/dashboard.html показывает 'Unknown'"
echo "Причина: Он настроен для продакшен сервера, а не для локального"
echo ""

echo "✅ РЕШЕНИЯ:"
echo ""

echo "1️⃣  ЛОКАЛЬНЫЙ ДАШБОРД (рекомендуется):"
echo "   → http://localhost:3001/dashboard.html"
echo "   → http://localhost:3001/ui/dashboard.html"
echo ""

echo "2️⃣  СДЕЛАТЬ СЕРВЕР ДОСТУПНЫМ ИЗ ИНТЕРНЕТА:"
echo "   brew install ngrok"
echo "   ngrok http 3002"
echo "   # Затем используйте ngrok URL в онлайн дашборде"
echo ""

echo "3️⃣  НАСТРОИТЬ ОНЛАЙН ДАШБОРД:"
echo "   1. Откройте https://sdk.stvor.xyz/dashboard.html" 
echo "   2. Нажмите F12 (Developer Tools)"
echo "   3. В консоли выполните:"
echo "   localStorage.setItem('stvor_relay_url', 'http://localhost:3002');"
echo "   location.reload();"
echo ""

# Проверка статуса
echo "📊 СТАТУС ВАШЕГО СЕРВЕРА:"
if curl -s -f http://localhost:3001/health > /dev/null; then
    echo "   ✅ API Server (3001) - работает"
else
    echo "   ❌ API Server (3001) - недоступен"
fi

if curl -s -f http://localhost:3002/health > /dev/null; then
    echo "   ✅ Relay Server (3002) - работает" 
else
    echo "   ❌ Relay Server (3002) - недоступен"
fi

echo ""
echo "🚀 БЫСТРЫЙ ПЕРЕХОД:"
echo "open http://localhost:3001/dashboard.html"