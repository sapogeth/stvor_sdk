# STVOR API - Production Deployment Guide

## 🚀 Запуск Relay Сервера в продакшене

У вас есть несколько вариантов для постоянной работы relay сервера:

### 🐳 **Вариант 1: Docker (Рекомендуемый)**

```bash
# Быстрый запуск
./deploy.sh docker

# Или вручную
docker-compose up -d
```

**Преимущества:**
- Автоматический перезапуск при сбое
- Изоляция окружения  
- Легкое масштабирование
- Включает PostgreSQL

**Порты:**
- API Server: `localhost:3001`
- HTTP Relay: `localhost:3002`
- PostgreSQL: `localhost:5433`

### ⚡ **Вариант 2: PM2 Process Manager**

```bash
# Установка и запуск
./deploy.sh pm2

# Управление
pm2 status                # Статус
pm2 logs                  # Логи
pm2 restart stvor-api     # Перезапуск
pm2 stop all             # Остановка
```

**Преимущества:**
- Автоматический перезапуск
- Мониторинг ресурсов
- Load balancing
- Логирование

### 🔧 **Вариант 3: SystemD System Service**

```bash
# Установка как системный сервис
./deploy.sh systemd

# Управление
sudo systemctl status stvor-api
sudo systemctl restart stvor-api
sudo systemctl stop stvor-api
```

**Преимущества:**
- Автозапуск при загрузке системы
- Системная интеграция
- Централизованное логирование

## 📊 **Мониторинг**

```bash
# Статус всех сервисов
./deploy.sh status

# Просмотр логов
./deploy.sh logs docker   # Docker logs
./deploy.sh logs pm2      # PM2 logs  
./deploy.sh logs systemd  # SystemD logs
```

## 🔧 **Конфигурация**

### Переменные среды (`.env`):
```bash
# Server Configuration
NODE_ENV=production
PORT=3001
RELAY_PORT=3002

# Database
DB_HOST=localhost
DB_PORT=5433
DB_USER=postgres
DB_PASSWORD=stvor123
DB_NAME=stvor
```

### Архитектура сервисов:

1. **Main API Server** (port 3001)
   - REST API endpoints
   - Authentication
   - Project management

2. **HTTP Relay Server** (port 3002)  
   - Message routing
   - Key exchange
   - User registration

3. **WebSocket Relay** (port 8080)
   - Real-time messaging
   - Live announcements

## 🛡️ **Безопасность в продакшене**

1. **Переменные среды:** Используйте безопасное хранение секретов
2. **HTTPS:** Настройте reverse proxy (nginx/apache)
3. **Firewall:** Ограничьте доступ к портам
4. **Monitoring:** Настройте алерты при сбоях

## ⚡ **Быстрый старт**

```bash
# 1. Клонируйте и перейдите в папку
cd stvor-api

# 2. Настройте окружение
cp .env.example .env
# Отредактируйте .env под ваши нужды

# 3. Выберите метод развертывания
./deploy.sh docker    # Рекомендуемый
./deploy.sh pm2        # Для Node.js окружения  
./deploy.sh systemd    # Для системной интеграции

# 4. Проверьте статус
./deploy.sh status
```

## 🆘 **Troubleshooting**

### Проблемы с портами:
```bash
# Проверить занятые порты
netstat -tulpn | grep :3001
netstat -tulpn | grep :3002

# Остановить процессы
./deploy.sh stop
```

### Проблемы с базой данных:
```bash
# Docker: перезапуск БД
docker-compose restart db

# Проверка подключения
docker exec stvor-db psql -U postgres -d stvor -c "SELECT 1;"
```

### Логи для диагностики:
```bash
./deploy.sh logs docker    # Все сервисы
docker-compose logs api     # Только API
docker-compose logs db      # Только БД
```

## 📈 **Performance & Scaling**

- **PM2 Clustering:** Включите cluster mode в `ecosystem.config.js`
- **Load Balancer:** Используйте nginx для распределения нагрузки
- **Database:** Настройте connection pooling для PostgreSQL
- **Caching:** Рассмотрите Redis для session storage

Relay сервер теперь будет автоматически перезапускаться при сбоях и работать постоянно! 🚀