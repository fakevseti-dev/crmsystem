# CRM.Orders

Система управления заказами для менеджеров. Поддержка СДЭК и Почты России.

## Стек

- **Backend:** Node.js + Express
- **База данных:** SQLite (better-sqlite3)
- **Frontend:** Vanilla JS SPA

## Запуск локально

```bash
npm install
npm start
# → http://localhost:3000
```

## Deploy на Hostinger

1. Загрузите репозиторий на GitHub
2. В Hostinger: **Add website → Node.js Web App → Deploy from GitHub**
3. Entry point: `server.js`
4. После деплоя база создаётся автоматически

## Аккаунты по умолчанию

| Логин | Пароль | Роль |
|-------|--------|------|
| `admin` | `admin123` | Администратор |
| `manager1` | `pass123` | Менеджер |

## Структура

```
├── server.js        ← Express сервер + REST API
├── package.json
├── public/
│   └── index.html   ← SPA фронтенд
└── crm.db           ← SQLite (создаётся автоматически, в .gitignore)
```

## API

```
POST /api/auth/login
POST /api/auth/logout
GET  /api/users
POST /api/users
POST /api/users/:id/toggle-login
POST /api/users/:id/toggle-save
PATCH /api/users/:id
GET  /api/orders
POST /api/orders
GET  /api/stats
GET  /api/stats/manager
```
