import sqlite3
import os
import csv
import hashlib
from datetime import datetime, timedelta
import glob
import logging
from pathlib import Path
import json
from urllib.parse import urlparse, parse_qs
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLineEdit, QComboBox, QTextEdit, QFileDialog, QLabel,
                             QMessageBox, QProgressDialog, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Set up logging with reduced verbosity in performance-critical sections
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parse_browser_history.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Transition type mappings
CHROMIUM_TRANSITION_TYPES = {
    0: 'Clicked Link', 1: 'User Typing', 2: 'Used Bookmark', 3: 'Embedded Auto Content',
    4: 'Embedded User Click', 5: 'Search Query', 6: 'Auto Page', 7: 'Form Submitted',
    8: 'Page Refreshed', 9: 'Keyword Search', 10: 'Keyword Query'
}

FIREFOX_TRANSITION_TYPES = {
    1: 'User Typing', 2: 'Clicked Link', 3: 'Used Bookmark', 4: 'Embedded Auto Content',
    5: 'Embedded User Click', 6: 'Search Query', 7: 'Page Refreshed', 8: 'Keyword Search',
    9: 'Keyword Query', 10: 'Synced Visit'
}

class IRBotInterface:
    def __init__(self):
        self.bot_name = "IR BOT"
        logger.info(f"Initialized {self.bot_name} interface")

    def send_data(self, data_type, data_summary):
        try:
            logger.info(f"{self.bot_name} received {data_type} data: {data_summary}")
            return True
        except Exception as e:
            logger.error(f"Error sending data to {self.bot_name}: {e}")
            return False

    def query_data(self, query_value, data, data_type):
        try:
            filtered_data = []
            query_value = query_value.strip().lower()
            try:
                query_date = datetime.strptime(query_value, '%Y-%m-%d').strftime('%m/%d/%Y')
                filtered_data = [item for item in data if item['timestamp'].startswith(query_date)]
                if filtered_data:
                    logger.info(f"{self.bot_name} processed date query '{query_value}' on {data_type}: found {len(filtered_data)} items")
                    return filtered_data
            except ValueError:
                pass
            if data_type == "downloads" and '.' in query_value:
                filtered_data = [item for item in data if query_value in item['filename'].lower()]
                if filtered_data:
                    logger.info(f"{self.bot_name} processed file query '{query_value}' on {data_type}: found {len(filtered_data)} items")
                    return filtered_data
            try:
                pattern = re.compile(query_value, re.IGNORECASE)
                filtered_data = [item for item in data if 'url' in item and pattern.search(item['url'])]
                if filtered_data:
                    logger.info(f"{self.bot_name} processed URL pattern query '{query_value}' on {data_type}: found {len(filtered_data)} items")
                    return filtered_data
            except re.error:
                pass
            filtered_data = [item for item in data if any(query_value in str(value).lower() for value in item.values())]
            logger.info(f"{self.bot_name} processed keyword query '{query_value}' on {data_type}: found {len(filtered_data)} items")
            return filtered_data
        except Exception as e:
            logger.error(f"Error processing query in {self.bot_name}: {e}")
            return []

def compute_file_hash(file_path):
    try:
        if os.path.isfile(file_path):
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        return "File not found"
    except Exception as e:
        logger.error(f"Error computing hash for {file_path}: {e}")
        return "Error"

def extract_search_keyword(url):
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param in ['q', 'query', 'search']:
            if param in query_params and query_params[param]:
                return query_params[param][0]
        return ""
    except Exception:
        return ""

def convert_chromium_timestamp(chromium_time):
    if not chromium_time or chromium_time <= 0:
        return ""
    try:
        epoch_start = datetime(1601, 1, 1)
        delta = timedelta(microseconds=chromium_time)
        return (epoch_start + delta).strftime('%m/%d/%Y %H:%M:%S')
    except Exception:
        return ""

def convert_firefox_timestamp(firefox_time):
    if not firefox_time or firefox_time <= 0:
        return ""
    try:
        return datetime.fromtimestamp(firefox_time / 1000000).strftime('%m/%d/%Y %H:%M:%S')
    except Exception:
        return ""

def ensure_indexes(db_file, browser_type):
    """Create temporary indexes to optimize query performance."""
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=rw', uri=True)
        cursor = conn.cursor()
        if browser_type == 'Chromium':
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_visits_url ON visits(url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_urls_id ON urls(id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_visits_visit_time ON visits(visit_time)")
        elif browser_type == 'Firefox':
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_moz_historyvisits_place_id ON moz_historyvisits(place_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_moz_places_id ON moz_places(id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_moz_historyvisits_visit_date ON moz_historyvisits(visit_date)")
        conn.commit()
    except sqlite3.Error as e:
        logger.warning(f"Error creating indexes for {db_file}: {e}")
    finally:
        if conn:
            conn.close()

def is_sqlite_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            return header.startswith(b'SQLite format 3')
    except Exception:
        return False

def detect_browser(db_file, manual_browser=None):
    if manual_browser and manual_browser != "Auto":
        return manual_browser
    if not os.path.exists(db_file) or not is_sqlite_file(db_file):
        return None
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
        if cursor.fetchone():
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='visits'")
            if cursor.fetchone():
                return 'Chromium'
            return 'Chromium'  # Allow partial Chromium artifacts
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_places'")
        if cursor.fetchone():
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_historyvisits'")
            if cursor.fetchone():
                return 'Firefox'
        return None
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()

def parse_chromium_history(db_file, search_keywords):
    visits = []
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        ensure_indexes(db_file, 'Chromium')
        query = """
        SELECT visits.id, urls.url, urls.title, visits.visit_time, visits.from_visit,
               visit_source.source, urls.typed_count, visits.transition
        FROM visits
        JOIN urls ON urls.id = visits.url
        LEFT JOIN visit_source ON visits.id = visit_source.id
        ORDER BY visits.visit_time DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        if not rows:
            query = """
            SELECT id, url, title, last_visit_time, typed_count
            FROM urls
            ORDER BY last_visit_time DESC
            """
            cursor.execute(query)
            rows = [(row['id'], row['url'], row['title'], row['last_visit_time'], 0, None, row['typed_count'], 0) for row in cursor.fetchall()]
        
        visit_dict = {}
        source_map = {0: 'Synced', 1: 'Browsed', 2: 'Extension', 3: 'Imported', 4: 'Imported', 5: 'Imported'}
        for row in rows:
            visit_id, url, title, visit_time, from_visit, source, typed_count, transition = row
            sync_status = source_map.get(source, 'Unknown') if source is not None else 'Unknown'
            core_transition = transition & 0x000000FF
            transition_meaning = CHROMIUM_TRANSITION_TYPES.get(core_transition, 'Unknown')
            formatted_time = convert_chromium_timestamp(visit_time)
            visit_data = {
                'visit_id': visit_id, 'url': url, 'title': title or '', 'timestamp': formatted_time,
                'from_visit': from_visit or 0, 'sync_status': sync_status, 'typed_count': typed_count or 0,
                'transition': core_transition, 'transition_meaning': transition_meaning,
                'redirection_chain': [], 'browser': 'Chromium', 'search_query': False, 'triggered_by_search': ''
            }
            visit_dict[visit_id] = visit_data
            if core_transition in [5, 9, 10]:
                keyword = extract_search_keyword(url)
                if keyword:
                    visit_data['search_query'] = True
                    visit_data['triggered_by_search'] = keyword
                    search_keywords.append({
                        'keyword': keyword, 'url': url, 'title': title or '',
                        'timestamp': formatted_time, 'browser': 'Chromium', 'visit_id': visit_id
                    })

        # Build redirection chains and search relationships efficiently
        search_visit_keywords = {sk['visit_id']: sk['keyword'] for sk in search_keywords if 'visit_id' in sk}
        search_to_next_visits = defaultdict(list)
        for visit_id, visit in visit_dict.items():
            if visit['from_visit'] in search_visit_keywords:
                visit['triggered_by_search'] = search_visit_keywords[visit['from_visit']]
                visit['search_query'] = False
            if visit['from_visit'] in search_visit_keywords:
                search_to_next_visits[visit['from_visit']].append(visit_id)
            
            chain = []
            current_id = visit_id
            visited_ids = set()
            while current_id in visit_dict and current_id not in visited_ids:
                chain.append(f"{current_id}:{visit_dict[current_id]['url']}")
                visited_ids.add(current_id)
                current_id = visit_dict[current_id]['from_visit']
            visit['redirection_chain'] = ' -> '.join(reversed(chain)) if chain else 'Direct'

        for sk in search_keywords:
            if 'visit_id' in sk:
                sk['redirection_chain'] = visit_dict.get(sk['visit_id'], {}).get('redirection_chain', 'Direct')
                sk['next_visits'] = ', '.join(map(str, search_to_next_visits.get(sk['visit_id'], [])))

        visits = list(visit_dict.values())
        return visits
    except sqlite3.Error as e:
        logger.error(f"Database error in parse_chromium_history: {e}")
        return visits
    finally:
        if conn:
            conn.close()

def parse_firefox_history(db_file, search_keywords):
    visits = []
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        ensure_indexes(db_file, 'Firefox')
        typed_counts = defaultdict(int)
        cursor.execute("""
        SELECT moz_places.id, COUNT(*) as typed_count
        FROM moz_historyvisits
        JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
        WHERE moz_historyvisits.visit_type = 1
        GROUP BY moz_places.id
        """)
        for row in cursor:
            typed_counts[row['id']] = row['typed_count']

        query = """
        SELECT moz_historyvisits.id, moz_places.url, moz_places.title,
               moz_historyvisits.visit_date, moz_historyvisits.from_visit,
               moz_historyvisits.visit_type, moz_places.id as place_id
        FROM moz_historyvisits
        JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
        ORDER BY moz_historyvisits.visit_date DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        visit_dict = {}
        for row in rows:
            visit_id, url, title, visit_date, from_visit, visit_type, place_id = row
            formatted_time = convert_firefox_timestamp(visit_date)
            sync_status = 'Synced' if visit_type == 10 else 'Local'
            typed_count = typed_counts.get(place_id, 0)
            transition_meaning = FIREFOX_TRANSITION_TYPES.get(visit_type, 'Unknown')
            visit_data = {
                'visit_id': visit_id, 'url': url, 'title': title or '', 'timestamp': formatted_time,
                'from_visit': from_visit or 0, 'sync_status': sync_status, 'typed_count': typed_count,
                'transition': visit_type, 'transition_meaning': transition_meaning,
                'redirection_chain': [], 'browser': 'Firefox', 'search_query': False, 'triggered_by_search': ''
            }
            visit_dict[visit_id] = visit_data
            if visit_type in [6, 8, 9] or 'search' in url.lower():
                keyword = extract_search_keyword(url)
                if keyword:
                    visit_data['search_query'] = True
                    visit_data['triggered_by_search'] = keyword
                    search_keywords.append({
                        'keyword': keyword, 'url': url, 'title': title or '',
                        'timestamp': formatted_time, 'browser': 'Firefox', 'visit_id': visit_id
                    })

        search_visit_keywords = {sk['visit_id']: sk['keyword'] for sk in search_keywords if 'visit_id' in sk}
        search_to_next_visits = defaultdict(list)
        for visit_id, visit in visit_dict.items():
            if visit['from_visit'] in search_visit_keywords:
                visit['triggered_by_search'] = search_visit_keywords[visit['from_visit']]
                visit['search_query'] = False
            if visit['from_visit'] in search_visit_keywords:
                search_to_next_visits[visit['from_visit']].append(visit_id)

            chain = []
            current_id = visit_id
            visited_ids = set()
            while current_id in visit_dict and current_id not in visited_ids:
                chain.append(f"{current_id}:{visit_dict[current_id]['url']}")
                visited_ids.add(current_id)
                current_id = visit_dict[current_id]['from_visit']
            visit['redirection_chain'] = ' -> '.join(reversed(chain)) if chain else 'Direct'

        for sk in search_keywords:
            if 'visit_id' in sk:
                sk['redirection_chain'] = visit_dict.get(sk['visit_id'], {}).get('redirection_chain', 'Direct')
                sk['next_visits'] = ', '.join(map(str, search_to_next_visits.get(sk['visit_id'], [])))

        visits = list(visit_dict.values())
        return visits
    except sqlite3.Error as e:
        logger.error(f"Database error in parse_firefox_history: {e}")
        return visits
    finally:
        if conn:
            conn.close()

def parse_chromium_downloads(db_file):
    downloads = []
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = """
        SELECT d.id, d.start_time, d.target_path, d.referrer, duc.url
        FROM downloads d
        LEFT JOIN downloads_url_chains duc ON d.id = duc.id
        WHERE duc.chain_index = (SELECT MAX(chain_index) FROM downloads_url_chains WHERE id = d.id)
        ORDER BY d.start_time DESC
        """
        cursor.execute(query)
        for row in cursor:
            formatted_time = convert_chromium_timestamp(row['start_time'])
            filename = os.path.basename(row['target_path']) if row['target_path'] else ""
            file_hash = compute_file_hash(row['target_path']) if row['target_path'] else "N/A"
            downloads.append({
                'download_id': row['id'], 'timestamp': formatted_time, 'filename': filename,
                'url': row['url'] or '', 'referrer': row['referrer'] or '', 'file_hash': file_hash, 'browser': 'Chromium'
            })
        return downloads
    except sqlite3.Error as e:
        logger.error(f"Database error in parse_chromium_downloads: {e}")
        return downloads
    finally:
        if conn:
            conn.close()

def parse_firefox_downloads(db_file):
    downloads = []
    conn = None
    try:
        conn = sqlite3.connect(f'file:{db_file}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_downloads'")
        moz_downloads_exists = cursor.fetchone() is not None
        if moz_downloads_exists:
            query = """
            SELECT id, name, source, startTime, referrer
            FROM moz_downloads
            ORDER BY startTime DESC
            """
            cursor.execute(query)
            for row in cursor:
                formatted_time = convert_firefox_timestamp(row['startTime'])
                filename = row['name'] or os.path.basename(row['source']) if row['source'] else ""
                file_hash = compute_file_hash(row['name']) if row['name'] and os.path.exists(row['name']) else "N/A"
                downloads.append({
                    'download_id': row['id'], 'timestamp': formatted_time, 'filename': filename,
                    'url': row['source'] or '', 'referrer': row['referrer'] or '', 'file_hash': file_hash, 'browser': 'Firefox'
                })
        if not downloads:
            query = """
            SELECT a.place_id, a.dateAdded, a.content, p.url,
                   (SELECT content FROM moz_annos r 
                    WHERE r.place_id = a.place_id 
                    AND r.anno_attribute_id = (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/referrer')) as referrer
            FROM moz_annos a
            JOIN moz_places p ON a.place_id = p.id
            JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
            WHERE aa.name = 'downloads/destinationFileName'
            ORDER BY a.dateAdded DESC
            """
            cursor.execute(query)
            download_id = 0
            for row in cursor:
                formatted_time = convert_firefox_timestamp(row['dateAdded'])
                try:
                    content = row['content']
                    filename = json.loads(content).get('fileName', os.path.basename(row['url']) if row['url'] else "") if content else os.path.basename(row['url']) if row['url'] else ""
                except json.JSONDecodeError:
                    filename = content or os.path.basename(row['url']) if row['url'] else ""
                file_hash = compute_file_hash(filename) if filename and os.path.exists(filename) else "N/A"
                downloads.append({
                    'download_id': f"FF_{row['place_id']}_{download_id}", 'timestamp': formatted_time, 'filename': filename,
                    'url': row['url'] or '', 'referrer': row['referrer'] or '', 'file_hash': file_hash, 'browser': 'Firefox'
                })
                download_id += 1
        return downloads
    except sqlite3.Error as e:
        logger.error(f"Database error in parse_firefox_downloads: {e}")
        return downloads
    finally:
        if conn:
            conn.close()

def parse_chromium_preferences(pref_file, browser_type):
    preferences = []
    try:
        with open(pref_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        account_info = data.get('account_info', [{}])[0]
        sync_data = data.get('sync', {})
        last_synced_time = 'N/A'
        for account_key, account_details in sync_data.get('transport_data_per_account', {}).items():
            last_synced_time = convert_chromium_timestamp(int(account_details.get('sync.last_synced_time', 0)))
            break
        data_types = sync_data.get('data_type_status_for_sync_to_signin', {})
        preferences = [
            {'name': "Account Email (0)", 'value': account_info.get('email', 'Unknown'), 'browser': 'Chrome'},
            {'name': "Account Name (0)", 'value': account_info.get('full_name', 'Unknown'), 'browser': 'Chrome'},
            {'name': "Last Sync Time", 'value': last_synced_time, 'browser': 'Chrome'},
            {'name': "Sync Apps", 'value': 'Yes' if data_types.get('apps', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Autofill", 'value': 'Yes' if data_types.get('autofill', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Bookmarks", 'value': 'Yes' if data_types.get('bookmarks', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Extensions", 'value': 'Yes' if data_types.get('extensions', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Passwords", 'value': 'Yes' if data_types.get('passwords', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Preferences", 'value': 'Yes' if data_types.get('preferences', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Tabs", 'value': 'Yes' if data_types.get('sessions', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Themes", 'value': 'Yes' if data_types.get('themes', False) else 'No', 'browser': 'Chrome'},
            {'name': "Sync Typed URLs", 'value': 'Yes' if data_types.get('history', False) else 'No', 'browser': 'Chrome'}
        ]
        return preferences
    except Exception as e:
        logger.error(f"Error parsing Chromium preferences: {e}")
        return preferences

def parse_firefox_preferences(profile_path, browser_type):
    preferences = []
    try:
        prefs_file = os.path.join(profile_path, 'prefs.js')
        if not os.path.exists(prefs_file):
            return preferences
        sync_email = 'Unknown'
        sync_name = 'Unknown'
        last_sync_time = 'N/A'
        sync_engines = {}
        with open(prefs_file, 'r', encoding='utf-8') as f:
            content = f.read()
            email_match = re.search(r'user_pref\("services\.sync\.username",\s*"([^"]+)"\);', content)
            if email_match:
                sync_email = email_match.group(1)
            name_match = re.search(r'user_pref\("identity\.fxaccounts\.account\.name",\s*"([^"]+)"\);', content)
            if name_match:
                sync_name = name_match.group(1)
            last_sync_match = re.search(r'user_pref\("services\.sync\.lastSync",\s*([^)]+)\);', content)
            if last_sync_match:
                try:
                    last_sync_timestamp = float(last_sync_match.group(1))
                    last_sync_time = convert_firefox_timestamp(last_sync_timestamp)
                except ValueError:
                    pass
            client_sync_match = re.search(r'user_pref\("services\.sync\.clients\.lastSync",\s*"([^"]+)"\);', content)
            if client_sync_match and client_sync_match.group(1) == "0":
                last_sync_time = 'N/A'
            engine_matches = re.findall(r'user_pref\("services\.sync\.engine\.([^"]+)",\s*(true|false)\);', content)
            for engine, enabled in engine_matches:
                sync_engines[engine] = enabled == 'true'

        preferences.append({'name': "Account Email (0)", 'value': sync_email, 'browser': 'Firefox'})
        preferences.append({'name': "Account Name (0)", 'value': sync_name, 'browser': 'Firefox'})
        preferences.append({'name': "Last Sync Time", 'value': last_sync_time, 'browser': 'Firefox'})
        engine_mapping = {
            'apps': 'Sync Apps', 'autofill': 'Sync Autofill', 'bookmarks': 'Sync Bookmarks',
            'extensions': 'Sync Extensions', 'passwords': 'Sync Passwords', 'prefs': 'Sync Preferences',
            'tabs': 'Sync Tabs', 'themes': 'Sync Themes', 'history': 'Sync Typed URLs'
        }
        for engine, enabled in sync_engines.items():
            if engine in engine_mapping:
                preferences.append({
                    'name': engine_mapping[engine],
                    'value': 'Yes' if enabled else 'No',
                    'browser': 'Firefox'
                })
        return preferences
    except Exception as e:
        logger.error(f"Error parsing Firefox preferences: {e}")
        return preferences

def get_unique_output_csv(output_dir, timestamp, suffix):
    base_name = f"{timestamp}_{suffix}.csv"
    output_csv = os.path.join(output_dir, base_name)
    counter = 1
    while os.path.exists(output_csv):
        output_csv = os.path.join(output_dir, f"{timestamp}_{suffix}_{counter}.csv")
        counter += 1
    return output_csv

def write_history_to_csv(visits, output_csv, browser, query_info=None):
    try:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            headers = ['Visit ID', 'URL', 'Title', 'Timestamp', 'From Visit ID', 'Sync Status', 'Typed Count',
                       'Transition', 'Transition Meaning', 'Redirection Chain', 'Search Query', 'Triggered by Search', 'Browser', 'Parsed At']
            if query_info:
                headers.append('Query')
            writer.writerow(headers)
            parsed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for visit in visits:
                row = [
                    visit['visit_id'], visit['url'], visit['title'], visit['timestamp'], visit['from_visit'] or '',
                    visit['sync_status'], visit['typed_count'], visit['transition'], visit['transition_meaning'],
                    visit['redirection_chain'], 'Yes' if visit.get('search_query', False) else 'No',
                    visit.get('triggered_by_search', ''), visit['browser'], parsed_at
                ]
                if query_info:
                    row.append(query_info)
                writer.writerow(row)
    except Exception as e:
        logger.error(f"Error writing history CSV: {e}")

def write_downloads_to_csv(downloads, output_csv, browser, query_info=None):
    try:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            headers = ['Download ID', 'Timestamp', 'Filename', 'URL', 'Referrer', 'File Hash', 'Browser', 'Parsed At']
            if query_info:
                headers.append('Query')
            writer.writerow(headers)
            parsed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for download in downloads:
                row = [
                    download['download_id'], download['timestamp'], download['filename'],
                    download['url'], download['referrer'], download['file_hash'], download['browser'], parsed_at
                ]
                if query_info:
                    row.append(query_info)
                writer.writerow(row)
    except Exception as e:
        logger.error(f"Error writing downloads CSV: {e}")

def write_preferences_to_csv(preferences, output_csv, browser, query_info=None):
    try:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            headers = ['Name', 'Value', 'Web Browser', 'Parsed At']
            if query_info:
                headers.append('Query')
            writer.writerow(headers)
            parsed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for pref in preferences:
                row = [pref['name'], pref['value'], pref['browser'], parsed_at]
                if query_info:
                    row.append(query_info)
                writer.writerow(row)
    except Exception as e:
        logger.error(f"Error writing preferences CSV: {e}")

def write_search_keywords_to_csv(search_keywords, output_csv, browser, query_info=None):
    try:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            headers = ['Keyword', 'URL', 'Title', 'Timestamp', 'Browser', 'Redirection Chain', 'Next Visits', 'Parsed At']
            if query_info:
                headers.append('Query')
            writer.writerow(headers)
            parsed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for sk in search_keywords:
                row = [
                    sk['keyword'], sk['url'], sk['title'], sk['timestamp'],
                    sk['browser'], sk['redirection_chain'] or 'Direct', sk.get('next_visits', ''), parsed_at
                ]
                if query_info:
                    row.append(query_info)
                writer.writerow(row)
    except Exception as e:
        logger.error(f"Error writing search keywords CSV: {e}")

def process_history_file(history_file, browser, processed_profiles):
    visits = []
    downloads = []
    preferences = []
    search_keywords = []
    detected_browser = detect_browser(history_file, browser if browser != "Auto" else None)
    if not detected_browser:
        return visits, downloads, preferences, search_keywords
    profile_path = os.path.dirname(history_file)
    try:
        if detected_browser == 'Firefox':
            if profile_path in processed_profiles:
                return visits, downloads, preferences, search_keywords
            processed_profiles.add(profile_path)
            visits = parse_firefox_history(history_file, search_keywords)
            downloads = parse_firefox_downloads(history_file)
            preferences = parse_firefox_preferences(profile_path, detected_browser)
        else:
            visits = parse_chromium_history(history_file, search_keywords)
            downloads = parse_chromium_downloads(history_file)
            pref_file = os.path.join(profile_path, 'Preferences')
            if os.path.exists(pref_file):
                preferences = parse_chromium_preferences(pref_file, detected_browser)
        return visits, downloads, preferences, search_keywords
    except Exception as e:
        logger.error(f"Error processing {history_file}: {e}")
        return visits, downloads, preferences, search_keywords

class ParserThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(list, list, list, list)
    error = pyqtSignal(str)
    log_message = pyqtSignal(str)

    def __init__(self, artifact_folder, browser):
        super().__init__()
        self.artifact_folder = artifact_folder
        self.browser = browser

    def run(self):
        try:
            # Find all unique profile directories containing relevant files
            profile_dirs = set()
            for pattern in ['**\\places.sqlite', '**\\prefs.js', '**\\History', '**\\Preferences']:
                files = glob.glob(os.path.join(self.artifact_folder, pattern), recursive=True)
                for file in files:
                    profile_dirs.add(os.path.dirname(file))

            if not profile_dirs:
                error_msg = "No browser profile directories found containing history or preference files."
                self.error.emit(error_msg)
                self.log_message.emit(error_msg)
                return

            total_profiles = len(profile_dirs)
            all_visits = []
            all_downloads = []
            all_preferences = []
            all_search_keywords = []

            for i, profile_dir in enumerate(profile_dirs):
                # Firefox history and downloads
                firefox_history_file = os.path.join(profile_dir, 'places.sqlite')
                if os.path.exists(firefox_history_file) and is_sqlite_file(firefox_history_file):
                    detected_browser = detect_browser(firefox_history_file, self.browser)
                    if detected_browser == 'Firefox':
                        search_keywords = []
                        visits = parse_firefox_history(firefox_history_file, search_keywords)
                        downloads = parse_firefox_downloads(firefox_history_file)
                        all_visits.extend(visits)
                        all_downloads.extend(downloads)
                        all_search_keywords.extend(search_keywords)
                        self.log_message.emit(f"Parsed Firefox history from {firefox_history_file}: {len(visits)} visits, {len(downloads)} downloads, {len(search_keywords)} search keywords")

                # Firefox preferences
                firefox_prefs_file = os.path.join(profile_dir, 'prefs.js')
                if os.path.exists(firefox_prefs_file):
                    preferences = parse_firefox_preferences(profile_dir, 'Firefox')
                    all_preferences.extend(preferences)
                    self.log_message.emit(f"Parsed Firefox preferences from {profile_dir}: {len(preferences)} preferences")

                # Chromium history and downloads
                chromium_history_file = os.path.join(profile_dir, 'History')
                if os.path.exists(chromium_history_file) and is_sqlite_file(chromium_history_file):
                    detected_browser = detect_browser(chromium_history_file, self.browser)
                    if detected_browser == 'Chromium':
                        search_keywords = []
                        visits = parse_chromium_history(chromium_history_file, search_keywords)
                        downloads = parse_chromium_downloads(chromium_history_file)
                        all_visits.extend(visits)
                        all_downloads.extend(downloads)
                        all_search_keywords.extend(search_keywords)
                        self.log_message.emit(f"Parsed Chromium history from {chromium_history_file}: {len(visits)} visits, {len(downloads)} downloads, {len(search_keywords)} search keywords")

                # Chromium preferences
                chromium_prefs_file = os.path.join(profile_dir, 'Preferences')
                if os.path.exists(chromium_prefs_file):
                    preferences = parse_chromium_preferences(chromium_prefs_file, 'Chromium')
                    all_preferences.extend(preferences)
                    self.log_message.emit(f"Parsed Chromium preferences from {profile_dir}: {len(preferences)} preferences")

                self.progress.emit(int((i + 1) / total_profiles * 100))

            self.finished.emit(all_visits, all_downloads, all_preferences, all_search_keywords)
            self.log_message.emit("Parsing completed successfully.")
        except Exception as e:
            self.error.emit(str(e))
            self.log_message.emit(f"Error in parsing: {str(e)}")

class BrowserHistoryParserGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ir_bot = IRBotInterface()
        self.initUI()
        self.output_dir = None
        self.all_visits = []
        self.all_downloads = []
        self.all_preferences = []
        self.all_search_keywords = []
        self.filtered_visits = []
        self.filtered_downloads = []
        self.filtered_preferences = []
        self.filtered_search_keywords = []
        self.last_query = None

    def initUI(self):
        self.setWindowTitle('ChronoBrowser')
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f2f5; }
            QPushButton { background-color: #4CAF50; color: white; padding: 8px 16px; border: none; border-radius: 4px; font-size: 14px; }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
            QLineEdit { padding: 8px; border: 1px solid #ddd; border-radius: 4px; background-color: white; font-size: 14px; }
            QLabel { font-size: 14px; color: #333; font-weight: bold; }
            QComboBox { padding: 8px; border: 1px solid #ddd; border-radius: 4px; background-color: white; font-size: 14px; }
            QTextEdit { background-color: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 8px; font-size: 12px; }
            QTableWidget { background-color: #fff; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; }
            QTabWidget::pane { border: 1px solid #ddd; border-radius: 4px; background-color: #fff; }
            QTabWidget::tab-bar { alignment: center; }
            QTabWidget QTabBar::tab { background: #f0f2f5; padding: 8px; border: 1px solid #ddd; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            QTabWidget QTabBar::tab:selected { background: #fff; border-bottom: 2px solid #4CAF50; }
        """)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        main_widget.setLayout(layout)
        title_label = QLabel("ChronoBrowser")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        trademark_label = QLabel("By Adib™")
        trademark_label.setFont(QFont("Arial", 10))
        trademark_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(trademark_label)
        artifact_layout = QHBoxLayout()
        self.artifact_label = QLabel("Artifact Folder:")
        self.artifact_path = QLineEdit()
        self.artifact_path.setReadOnly(True)
        self.artifact_button = QPushButton("Browse")
        self.artifact_button.clicked.connect(self.browse_artifact)
        artifact_layout.addWidget(self.artifact_label)
        artifact_layout.addWidget(self.artifact_path)
        artifact_layout.addWidget(self.artifact_button)
        layout.addLayout(artifact_layout)
        output_layout = QHBoxLayout()
        self.output_label = QLabel("Output Directory:")
        self.output_path = QLineEdit()
        self.output_path.setReadOnly(True)
        self.output_button = QPushButton("Browse")
        self.output_button.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.output_path)
        output_layout.addWidget(self.output_button)
        layout.addLayout(output_layout)
        browser_layout = QHBoxLayout()
        self.browser_label = QLabel("Browser:")
        self.browser_combo = QComboBox()
        self.browser_combo.addItems(["Auto", "Chromium", "Firefox"])
        browser_layout.addWidget(self.browser_label)
        browser_layout.addWidget(self.browser_combo)
        layout.addLayout(browser_layout)
        self.parse_button = QPushButton("Parse Artifacts")
        self.parse_button.clicked.connect(self.start_parsing)
        layout.addWidget(self.parse_button)
        query_layout = QHBoxLayout()
        self.query_label = QLabel("Search:")
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Enter search term (e.g., python, 2025-05-06, .pdf)")
        self.query_button = QPushButton("Run Query")
        self.query_button.clicked.connect(self.perform_query)
        self.clear_filter_button = QPushButton("Clear Filter")
        self.clear_filter_button.clicked.connect(self.clear_filter)
        self.clear_filter_button.setEnabled(False)
        query_layout.addWidget(self.query_label)
        query_layout.addWidget(self.query_input)
        query_layout.addWidget(self.query_button)
        query_layout.addWidget(self.clear_filter_button)
        layout.addLayout(query_layout)
        self.filter_indicator = QLabel("")
        self.filter_indicator.setFont(QFont("Arial", 12, QFont.Bold))
        self.filter_indicator.setStyleSheet("color: #e74c3c;")
        self.filter_indicator.setAlignment(Qt.AlignCenter)
        self.filter_indicator.hide()
        layout.addWidget(self.filter_indicator)
        export_layout = QHBoxLayout()
        self.export_button = QPushButton("Export Query Results")
        self.export_button.clicked.connect(self.export_query_results)
        self.export_button.setEnabled(False)
        export_layout.addStretch()
        export_layout.addWidget(self.export_button)
        layout.addLayout(export_layout)
        self.tab_widget = QTabWidget()
        self.history_table = QTableWidget()
        self.downloads_table = QTableWidget()
        self.preferences_table = QTableWidget()
        self.keyword_searched_table = QTableWidget()
        self.tab_widget.addTab(self.history_table, "History (0)")
        self.tab_widget.addTab(self.downloads_table, "Downloads (0)")
        self.tab_widget.addTab(self.preferences_table, "Preferences (0)")
        self.tab_widget.addTab(self.keyword_searched_table, "Keyword Searched (0)")
        self.history_table.doubleClicked.connect(self.show_full_cell_value)
        self.downloads_table.doubleClicked.connect(self.show_full_cell_value)
        self.preferences_table.doubleClicked.connect(self.show_full_cell_value)
        self.keyword_searched_table.doubleClicked.connect(self.show_full_cell_value)
        layout.addWidget(self.tab_widget)
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(100)
        layout.addWidget(self.log_area)

    def browse_artifact(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Artifact Folder", "")
        if folder_path:
            self.artifact_path.setText(folder_path)

    def browse_output(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", "")
        if dir_path:
            self.output_path.setText(dir_path)
            self.output_dir = dir_path

    def append_log(self, message):
        self.log_area.append(message)
        self.log_area.ensureCursorVisible()

    def show_full_cell_value(self, index):
        table = self.sender()
        if not table or not index.isValid():
            return
        item = table.item(index.row(), index.column())
        if not item:
            return
        value = item.text() or "(Empty)"
        header = table.horizontalHeaderItem(index.column())
        header_text = header.text() if header else "Value"
        dialog = QMessageBox(self)
        dialog.setWindowTitle(f"{header_text}")
        dialog.setText(value)
        dialog.setStyleSheet("QLabel { min-width: 400px; max-width: 600px; }")
        dialog.setStandardButtons(QMessageBox.Ok)
        dialog.exec_()

    def setup_history_table(self, visits):
        self.history_table.clear()
        self.history_table.setRowCount(len(visits))
        self.history_table.setColumnCount(12)
        self.history_table.setHorizontalHeaderLabels([
            'Visit ID', 'URL', 'Title', 'Timestamp', 'From Visit ID',
            'Sync Status', 'Typed Count', 'Transition', 'Transition Meaning', 'Redirection Chain',
            'Search Query', 'Triggered by Search'
        ])
        for row, visit in enumerate(visits):
            self.history_table.setItem(row, 0, QTableWidgetItem(str(visit['visit_id'])))
            self.history_table.setItem(row, 1, QTableWidgetItem(visit['url']))
            self.history_table.setItem(row, 2, QTableWidgetItem(visit['title']))
            self.history_table.setItem(row, 3, QTableWidgetItem(visit['timestamp']))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(visit['from_visit'])))
            self.history_table.setItem(row, 5, QTableWidgetItem(visit['sync_status']))
            self.history_table.setItem(row, 6, QTableWidgetItem(str(visit['typed_count'])))
            self.history_table.setItem(row, 7, QTableWidgetItem(str(visit['transition'])))
            self.history_table.setItem(row, 8, QTableWidgetItem(visit['transition_meaning']))
            self.history_table.setItem(row, 9, QTableWidgetItem(visit['redirection_chain']))
            self.history_table.setItem(row, 10, QTableWidgetItem('Yes' if visit.get('search_query', False) else 'No'))
            self.history_table.setItem(row, 11, QTableWidgetItem(visit.get('triggered_by_search', '')))
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.resizeColumnsToContents()
        self.history_table.setSortingEnabled(True)
        self.tab_widget.setTabText(0, f"History ({len(visits)})")

    def setup_downloads_table(self, downloads):
        self.downloads_table.clear()
        self.downloads_table.setRowCount(len(downloads))
        self.downloads_table.setColumnCount(6)
        self.downloads_table.setHorizontalHeaderLabels(['Download ID', 'Timestamp', 'Filename', 'URL', 'Referrer', 'File Hash'])
        for row, download in enumerate(downloads):
            self.downloads_table.setItem(row, 0, QTableWidgetItem(str(download['download_id'])))
            self.downloads_table.setItem(row, 1, QTableWidgetItem(download['timestamp']))
            self.downloads_table.setItem(row, 2, QTableWidgetItem(download['filename']))
            self.downloads_table.setItem(row, 3, QTableWidgetItem(download['url']))
            self.downloads_table.setItem(row, 4, QTableWidgetItem(download['referrer']))
            self.downloads_table.setItem(row, 5, QTableWidgetItem(download['file_hash']))
        self.downloads_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.downloads_table.horizontalHeader().setStretchLastSection(True)
        self.downloads_table.resizeColumnsToContents()
        self.downloads_table.setSortingEnabled(True)
        self.tab_widget.setTabText(1, f"Downloads ({len(downloads)})")

    def setup_preferences_table(self, preferences):
        self.preferences_table.clear()
        self.preferences_table.setRowCount(len(preferences))
        self.preferences_table.setColumnCount(3)
        self.preferences_table.setHorizontalHeaderLabels(['Name', 'Value', 'Web Browser'])
        for row, pref in enumerate(preferences):
            self.preferences_table.setItem(row, 0, QTableWidgetItem(pref['name']))
            self.preferences_table.setItem(row, 1, QTableWidgetItem(pref['value']))
            self.preferences_table.setItem(row, 2, QTableWidgetItem(pref['browser']))
        self.preferences_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.preferences_table.horizontalHeader().setStretchLastSection(True)
        self.preferences_table.resizeColumnsToContents()
        self.preferences_table.setSortingEnabled(True)
        self.tab_widget.setTabText(2, f"Preferences ({len(preferences)})")

    def setup_keyword_searched_table(self, search_keywords):
        self.keyword_searched_table.clear()
        self.keyword_searched_table.setRowCount(len(search_keywords))
        self.keyword_searched_table.setColumnCount(6)
        self.keyword_searched_table.setHorizontalHeaderLabels(['Keyword', 'URL', 'Title', 'Timestamp', 'Redirection Chain', 'Next Visits'])
        for row, sk in enumerate(search_keywords):
            self.keyword_searched_table.setItem(row, 0, QTableWidgetItem(sk['keyword']))
            self.keyword_searched_table.setItem(row, 1, QTableWidgetItem(sk['url']))
            self.keyword_searched_table.setItem(row, 2, QTableWidgetItem(sk['title']))
            self.keyword_searched_table.setItem(row, 3, QTableWidgetItem(sk['timestamp']))
            self.keyword_searched_table.setItem(row, 4, QTableWidgetItem(sk['redirection_chain'] or 'Direct'))
            self.keyword_searched_table.setItem(row, 5, QTableWidgetItem(sk.get('next_visits', '')))
        self.keyword_searched_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.keyword_searched_table.horizontalHeader().setStretchLastSection(True)
        self.keyword_searched_table.resizeColumnsToContents()
        self.keyword_searched_table.setSortingEnabled(True)
        self.tab_widget.setTabText(3, f"Keyword Searched ({len(search_keywords)})")

    def perform_query(self):
        query_value = self.query_input.text().strip()
        if not query_value:
            self.clear_filter()
            return
        self.last_query = query_value
        self.filtered_visits = self.ir_bot.query_data(query_value, self.all_visits, "history")
        self.filtered_downloads = self.ir_bot.query_data(query_value, self.all_downloads, "downloads")
        self.filtered_preferences = self.ir_bot.query_data(query_value, self.all_preferences, "preferences")
        self.filtered_search_keywords = self.ir_bot.query_data(query_value, self.all_search_keywords, "search_keywords")
        self.setup_history_table(self.filtered_visits)
        self.setup_downloads_table(self.filtered_downloads)
        self.setup_preferences_table(self.filtered_preferences)
        self.setup_keyword_searched_table(self.filtered_search_keywords)
        self.filter_indicator.setText(f"Filtered by: {query_value}")
        self.filter_indicator.show()
        self.clear_filter_button.setEnabled(True)
        self.export_button.setEnabled(bool(self.filtered_visits or self.filtered_downloads or self.filtered_preferences))
        self.append_log(f"Search for '{query_value}' completed: {len(self.filtered_visits)} visits, "
                        f"{len(self.filtered_downloads)} downloads, {len(self.filtered_preferences)} preferences, "
                        f"{len(self.filtered_search_keywords)} search keywords found.")

    def clear_filter(self):
        self.query_input.clear()
        self.last_query = None
        self.filtered_visits = self.all_visits
        self.filtered_downloads = self.all_downloads
        self.filtered_preferences = self.all_preferences
        self.filtered_search_keywords = self.all_search_keywords
        self.setup_history_table(self.filtered_visits)
        self.setup_downloads_table(self.filtered_downloads)
        self.setup_preferences_table(self.filtered_preferences)
        self.setup_keyword_searched_table(self.filtered_search_keywords)
        self.filter_indicator.hide()
        self.clear_filter_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.append_log("Filter cleared, showing all data.")

    def export_query_results(self):
        if not self.output_dir or not self.last_query:
            QMessageBox.critical(self, "Error", "Output directory or query not set.")
            return
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        query_info = f"search: {self.last_query}"
        if self.filtered_visits:
            output_history_csv = get_unique_output_csv(self.output_dir, timestamp, f"query_history_{self.last_query.replace(' ', '_')}")
            write_history_to_csv(self.filtered_visits, output_history_csv, "Filtered", query_info)
            QMessageBox.information(self, "Success", f"Filtered history exported to {output_history_csv}")
            self.append_log(f"Filtered history exported to {output_history_csv}")
        if self.filtered_downloads:
            output_downloads_csv = get_unique_output_csv(self.output_dir, timestamp, f"query_downloads_{self.last_query.replace(' ', '_')}")
            write_downloads_to_csv(self.filtered_downloads, output_downloads_csv, "Filtered", query_info)
            QMessageBox.information(self, "Success", f"Filtered downloads exported to {output_downloads_csv}")
            self.append_log(f"Filtered downloads exported to {output_downloads_csv}")
        if self.filtered_preferences:
            output_preferences_csv = get_unique_output_csv(self.output_dir, timestamp, f"query_preferences_{self.last_query.replace(' ', '_')}")
            write_preferences_to_csv(self.filtered_preferences, output_preferences_csv, "Filtered", query_info)
            QMessageBox.information(self, "Success", f"Filtered preferences exported to {output_preferences_csv}")
            self.append_log(f"Filtered preferences exported to {output_preferences_csv}")
        if not (self.filtered_visits or self.filtered_downloads or self.filtered_preferences):
            QMessageBox.warning(self, "Warning", "No filtered data to export.")

    def start_parsing(self):
        artifact_folder = self.artifact_path.text()
        if not artifact_folder or not os.path.isdir(artifact_folder):
            QMessageBox.critical(self, "Error", "Please select a valid artifact folder.")
            return
        if not self.output_dir or not os.path.isdir(self.output_dir):
            QMessageBox.critical(self, "Error", "Please select a valid output directory.")
            return
        self.parse_button.setEnabled(False)
        self.log_area.clear()
        self.history_table.setRowCount(0)
        self.downloads_table.setRowCount(0)
        self.preferences_table.setRowCount(0)
        self.keyword_searched_table.setRowCount(0)
        self.tab_widget.setTabText(0, "History (0)")
        self.tab_widget.setTabText(1, "Downloads (0)")
        self.tab_widget.setTabText(2, "Preferences (0)")
        self.tab_widget.setTabText(3, "Keyword Searched (0)")
        self.query_input.clear()
        self.filter_indicator.hide()
        self.clear_filter_button.setEnabled(False)
        self.filtered_visits = []
        self.filtered_downloads = []
        self.filtered_preferences = []
        self.all_search_keywords = []
        self.filtered_search_keywords = []
        self.last_query = None
        self.export_button.setEnabled(False)
        self.progress_dialog = QProgressDialog("Parsing artifacts...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setAutoClose(True)
        self.progress_dialog.setAutoReset(True)
        self.progress_dialog.show()
        self.parser_thread = ParserThread(artifact_folder, self.browser_combo.currentText())
        self.parser_thread.progress.connect(self.update_progress)
        self.parser_thread.finished.connect(self.parsing_finished)
        self.parser_thread.error.connect(self.parsing_error)
        self.parser_thread.log_message.connect(self.append_log)
        self.parser_thread.start()

    def update_progress(self, value):
        self.progress_dialog.setValue(value)

    def parsing_finished(self, visits, downloads, preferences, search_keywords):
        self.parse_button.setEnabled(True)
        self.progress_dialog.close()
        self.all_visits = visits
        self.all_downloads = downloads
        self.all_preferences = preferences
        self.all_search_keywords = search_keywords
        self.filtered_visits = visits
        self.filtered_downloads = downloads
        self.filtered_preferences = preferences
        self.filtered_search_keywords = search_keywords
        self.setup_history_table(visits)
        self.setup_downloads_table(downloads)
        self.setup_preferences_table(preferences)
        self.setup_keyword_searched_table(search_keywords)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        download_pattern = re.compile(r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|zip|rar|exe|jpg|jpeg|png|gif|mp3|mp4|avi|mkv|iso|dmg|tar|gz)$', re.IGNORECASE)
        inferred_downloads = []
        if not downloads and visits:
            for visit in visits:
                if not visit['url'] or not visit['timestamp']:
                    continue
                parsed_url = urlparse(visit['url'])
                path = parsed_url.path
                if download_pattern.search(path):
                    filename = os.path.basename(path) or "unknown_file"
                    inferred_downloads.append({
                        'download_id': f"FF_{visit['visit_id']}", 'timestamp': visit['timestamp'],
                        'filename': filename, 'url': visit['url'], 'referrer': '', 'file_hash': 'N/A', 'browser': 'Firefox'
                    })
        if inferred_downloads:
            self.all_downloads = inferred_downloads
            self.filtered_downloads = inferred_downloads
            self.setup_downloads_table(inferred_downloads)
        if visits:
            output_history_csv = get_unique_output_csv(self.output_dir, timestamp, "combined_history")
            write_history_to_csv(visits, output_history_csv, "Combined")
            QMessageBox.information(self, "Success", f"History data exported to {output_history_csv}")
            self.append_log(f"History data exported to {output_history_csv}")
        if self.all_downloads:
            output_downloads_csv = get_unique_output_csv(self.output_dir, timestamp, "combined_downloads")
            write_downloads_to_csv(self.all_downloads, output_downloads_csv, "Combined")
            QMessageBox.information(self, "Success", f"Downloads data exported to {output_downloads_csv}")
            self.append_log(f"Downloads data exported to {output_downloads_csv}")
        if preferences:
            output_preferences_csv = get_unique_output_csv(self.output_dir, timestamp, "combined_preferences")
            write_preferences_to_csv(preferences, output_preferences_csv, "Combined")
            QMessageBox.information(self, "Success", f"Preferences data exported to {output_preferences_csv}")
            self.append_log(f"Preferences data exported to {output_preferences_csv}")
        if search_keywords:
            output_keywords_csv = get_unique_output_csv(self.output_dir, timestamp, "search_keywords")
            write_search_keywords_to_csv(search_keywords, output_keywords_csv, "Combined")
            QMessageBox.information(self, "Success", f"Search keywords exported to {output_keywords_csv}")
            self.append_log(f"Search keywords exported to {output_keywords_csv}")
        if not (visits or self.all_downloads or preferences or search_keywords):
            QMessageBox.warning(self, "Warning", "No data found to export.")
            self.append_log("Warning: No data found to export.")

    def parsing_error(self, error_msg):
        QMessageBox.critical(self, "Error", f"Parsing error: {error_msg}")
        self.append_log(f"Error: {error_msg}")
        self.parse_button.setEnabled(True)
        self.progress_dialog.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('C:/Users/Furryz/Desktop/project/BrowserHistoryParser/chrono.ico'))
    window = BrowserHistoryParserGUI()
    window.show()
    sys.exit(app.exec_())