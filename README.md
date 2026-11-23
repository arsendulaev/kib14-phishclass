# PhishClass

Веб-приложение для экспресс-анализа подозрительных писем и URL. Определяет возможные техники фишинга, объясняет их риски и составляет чеклист реагирования.

## Запуск

Нужен Python 3.10 или новее. Для анализа через GPT перед запуском задайте `export OPENAI_API_KEY="ваш_ключ"`. Без ключа используется локальный анализ.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```
