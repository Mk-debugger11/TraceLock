from app.settings import load_settings


def main():
    settings = load_settings("settings.yaml")
    print(settings)


if __name__ == "__main__":
    main()
