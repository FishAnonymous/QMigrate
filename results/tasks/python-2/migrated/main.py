from crypto_adapter import selftest
import json

def main():
    result = selftest()
    print(json.dumps(result))
    if result["status"] != "passed":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
