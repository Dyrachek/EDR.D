# EDR.D

Локальная мини-система Endpoint Detection and Response для Windows.

Десктопное приложение для мониторинга процессов, сетевых соединений, автозагрузки и базовой детекции подозрительной активности. Встроенный AI-ассистент на локальной SLM.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flet](https://img.shields.io/badge/UI-Flet-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

---

## Возможности

### Мониторинг
- Процессы: CPU, память, путь, статус
- Группировка процессов (как в Диспетчере задач)
- Поиск по имени процесса
- Завершение процессов

### Сеть
- Активные TCP/UDP соединения
- Группировка по процессам
- Подсветка подозрительных соединений

### Детекция
- Подозрительные имена процессов
- Запуск из Temp / Downloads / AppData
- Аномальная нагрузка CPU / Memory
- Белый список доверенных процессов

### Автозагрузка
- Программы из реестра Windows (HKCU / HKLM)

### История
- Сохранение алертов в JSON
- Экспорт истории
- Очистка

### AI-ассистент (локальная модель)
- Сводка сессии
- Объяснение алертов
- Анализ процесса
- Работает **офлайн**, модель в папке `models/`

### Прочее
- Автозапуск с Windows
- Тёмный интерфейс

---

## Требования

- Windows 10/11
- Python 3.10+
- ~2 GB RAM для AI-модели


## Технологии

Python 3
Flet — UI
psutil — процессы и сеть
llama-cpp-python — локальный инференс
winreg — автозагрузка и автозапуск


---

## Установка

```bash
git clone https://github.com/Dyrachek/MiniEDR.git
cd MiniEDR
pip install -r requirements.txt

**python download_model.py**

---



