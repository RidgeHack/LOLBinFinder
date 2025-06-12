import requests
import os

LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
OUTPUT_FILE = "lolbas_paths.txt"

def fetch_lolbas_data(url):
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def extract_all_paths(data):
    paths = set()

    def recurse(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "Path" and isinstance(value, str):
                    paths.add(value.strip())
                else:
                    recurse(value)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(data)
    return sorted(paths)

def save_paths_to_file(paths, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for path in paths:
            f.write(path + "\n")

def main():
    print(f"🔍 Fetching data from: {LOLBAS_API_URL}")
    data = fetch_lolbas_data(LOLBAS_API_URL)
    paths = extract_all_paths(data)
    save_paths_to_file(paths, OUTPUT_FILE)
    print(f"✅ Saved {len(paths)} paths to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    main()
