import requests
from urllib.parse import urljoin

API_URL = "https://hijacklibs.net/api/hijacklibs.json"

def fetch_api_data(url):
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def extract_paths_and_dlls(entries):
    dll_full_paths = set()

    for entry in entries:
        dll = entry.get("Name") or entry.get("dll")
        if not dll:
            continue

        expected_locations = entry.get("ExpectedLocations", [])
        if isinstance(expected_locations, str):
            locations = [loc.strip() for loc in expected_locations.split(',') if loc.strip()]
        elif isinstance(expected_locations, list):
            locations = expected_locations
        else:
            continue

        for folder in locations:
            folder = folder.strip().rstrip('\\/')
            if folder:
                normalized_folder = folder.replace("\\", "/")
                dll_full_paths.add(f"{normalized_folder}/{dll}")

    return sorted(dll_full_paths)

def save_to_txt(filename, lines):
    with open(filename, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

def main():
    print(f"🔍 Fetching data from: {API_URL}")
    entries = fetch_api_data(API_URL)

  
    full_dll_paths = extract_paths_and_dlls(entries)

    save_to_txt("vulnerable_dlls.txt", full_dll_paths)

    print(f"✅ Saved {len(full_dll_paths)} DLL paths to 'vulnerable_dlls.txt'")

if __name__ == "__main__":
    main()
