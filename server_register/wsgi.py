# wsgi.py
import os
import sys

# Добавляем путь к проекту в Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from server_tilda import app

# Для совместимости с различными WSGI серверами
application = app

if __name__ == "__main__":
    # Только для разработки
    app.run(debug=False, host='0.0.0.0', port=5000)
