import builtwith


def detect_technologies(domain):
    print(f"\nDetectando tecnologias de {domain}:")
    try:
        info = builtwith.parse(f"https://{domain}")
        if info:
            for category, techs in info.items():
                print(f"  {category}: {', '.join(techs)}")
        else:
            print("  No se detectaron tecnologias")
        return info
    except Exception as e:
        print(f"  Error: {e}")
        return {}