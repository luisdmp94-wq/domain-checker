from datetime import datetime
import json


def save_report(data, domain):
    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Reporte JSON guardado en: {filename}")