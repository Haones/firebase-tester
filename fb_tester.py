#!/usr/bin/env python3
"""
Firebase Configuration Security Testing Tool
Tests Firebase configurations for potential security misconfigurations

Usage examples:
    
    # Parse JSON config with quoted keys
    python3 firebase_test.py --firebase-config '{"apiKey":"AIza...","authDomain":"proj.firebaseapp.com"}'
    
    # Parse JavaScript config with unquoted keys
    python3 firebase_test.py --firebase-config '{apiKey:"AIza...",authDomain:"proj.firebaseapp.com"}'
    
    # Parse multiline config 
    python3 firebase_test.py --firebase-config '{
      apiKey: "AIza...",
      authDomain: "proj.firebaseapp.com"
    }'
    
    # Individual parameters
    python3 firebase_test.py --api-key "AIza..." --database-url "https://proj.firebaseio.com"
    
    # Debug mode (prints curl commands for each test)
    python3 firebase_test.py --firebase-config '...' --debug
    
    # Custom email/password for registration test
    python3 firebase_test.py --firebase-config '...' --email "test@example.com" --password "Pa$w0rd"
"""

import argparse
import json
import random
import string
import sys
import requests
from urllib.parse import quote
import base64
import re
from typing import Dict, Optional, Any

class FirebaseConfigTester:
    def __init__(self, config: Dict[str, str], debug: bool = False):
        self.config = self._parse_config(config)
        self.debug = debug
        self.id_token = None
        self.random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
    def _parse_config(self, config: Dict[str, str]) -> Dict[str, str]:
        """Parse and clean the Firebase configuration"""
        # Handle unicode escape sequences
        config_str = json.dumps(config)
        config_str = config_str.encode().decode('unicode_escape')
        
        # Clean up the config (remove quotes, spaces, etc.)
        cleaned_config = {}
        for key, value in json.loads(config_str).items():
            if value:
                cleaned_config[key] = str(value).strip()
        
        return cleaned_config
    
    def _print_debug(self, message: str, curl_command: str = None):
        """Print debug information if debug mode is enabled"""
        if self.debug:
            print(f"DEBUG: {message}")
            if curl_command:
                print(f"CURL: {curl_command}")
    
    def check_registration(self, email: str, password: str) -> bool:
        """Check if registration is possible with provided apiKey"""
        if 'apiKey' not in self.config:
            print("No apiKey provided, skipping registration check")
            return False
        
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.config['apiKey']}"
        headers = {'Content-Type': 'application/json'}
        data = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        curl_cmd = f"curl '{url}' -H 'Content-Type: application/json' --data '{json.dumps(data)}'"
        self._print_debug(f"Checking registration at {url}", curl_cmd)
        
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                print(f"✓ Registration successful with apiKey")
                result = response.json()
                self.id_token = result.get('idToken')
                return True
            elif response.status_code == 400:
                print(f"✗ Registration not allowed (status: {response.status_code})")
                return False
            else:
                print(f"✗ Registration check failed (status: {response.status_code})")
                return False
        except Exception as e:
            print(f"✗ Registration check error: {e}")
            return False
    
    def check_storage_bucket(self):
        """Check if storageBucket is accessible"""
        if 'storageBucket' not in self.config:
            print("No storageBucket provided, skipping check")
            return
        
        storage_bucket = self.config['storageBucket']
        
        # Check via firebasestorage.googleapis.com
        print(f"\nChecking storage bucket: {storage_bucket}")
        
        # Test anonymous, authenticated legacy (Bearer), and modern (Firebase)
        headers_list = [{}]
        if self.id_token:
            headers_list.append({"Authorization": f"Bearer {self.id_token}"})
            headers_list.append({"Authorization": f"Firebase {self.id_token}"})
        
        for i, headers in enumerate(headers_list):
            if not headers:
                auth_type = "anonymous"
            elif "Bearer" in headers.get("Authorization", ""):
                auth_type = "authenticated (Bearer)"
            else:
                auth_type = "authenticated (Firebase)"
            
            # Firebase Storage API
            url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o"
            curl_cmd = f"curl '{url}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Checking {url} ({auth_type})", curl_cmd)
            
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print(f"✓ Storage bucket accessible ({auth_type})")
                    print(f"  URL: {url}")
                    
                    # Save storage listing to file
                    try:
                        listing_data = response.json()
                        filename = f"storage-listing-{auth_type.replace(' ', '-').replace('(', '').replace(')', '')}.json"
                        with open(filename, 'w') as f:
                            json.dump(listing_data, f, indent=2)
                        print(f"  Listing saved to {filename}")
                    except Exception as e:
                        print(f"  Could not save listing: {e}")
                        
                elif response.status_code == 404:
                    print(f"✗ Storage bucket not found ({auth_type})")
                else:
                    print(f"✗ Storage bucket check failed ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Storage bucket check error ({auth_type}): {e}")
            
            # Google Cloud Storage API
            url = f"https://storage.googleapis.com/{storage_bucket}/"
            curl_cmd = f"curl '{url}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Checking {url} ({auth_type})", curl_cmd)
            
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print(f"✓ Google Cloud Storage accessible ({auth_type})")
                    print(f"  URL: {url}")
            except Exception as e:
                print(f"✗ Google Cloud Storage check error ({auth_type}): {e}")
    
    def check_storage_upload(self):
        """Check if uploading to storageBucket is possible"""
        if 'storageBucket' not in self.config:
            print("No storageBucket provided, skipping upload check")
            return
        
        storage_bucket = self.config['storageBucket']
        filename = f"poc_{self.random_string}.json"
        upload_data = {"poc": self.random_string}
        
        print(f"\nChecking storage upload capability")
        
        # Test anonymous, authenticated legacy (Bearer), and modern (Firebase)
        headers_list = [{"Content-Type": "application/json"}]
        if self.id_token:
            headers_list.append({
                "Authorization": f"Bearer {self.id_token}",
                "Content-Type": "application/json"
            })
            headers_list.append({
                "Authorization": f"Firebase {self.id_token}",
                "Content-Type": "application/json"
            })
        
        for i, headers in enumerate(headers_list):
            if "Authorization" not in headers:
                auth_type = "anonymous"
            elif "Bearer" in headers.get("Authorization", ""):
                auth_type = "authenticated (Bearer)"
            else:
                auth_type = "authenticated (Firebase)"
            
            # Upload file
            url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o?name={filename}"
            curl_cmd = f"curl -X POST '{url}' -H 'Content-Type: application/json'"
            if "Authorization" in headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            curl_cmd += f" -d '{json.dumps(upload_data)}'"
            self._print_debug(f"Attempting upload ({auth_type})", curl_cmd)
            
            try:
                response = requests.post(url, headers=headers, json=upload_data)
                if response.status_code == 200:
                    print(f"✓ Upload successful ({auth_type})")
                    
                    # Verify upload
                    verify_url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o/{filename}?alt=media"
                    verify_response = requests.get(verify_url)
                    if verify_response.status_code == 200:
                        print(f"✓ Upload verified ({auth_type})")
                        print(f"  URL: {verify_url}")
                else:
                    print(f"✗ Upload failed ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Upload check error ({auth_type}): {e}")
    
    def check_database_accessibility(self):
        """Check general database accessibility for common endpoints"""
        if 'databaseURL' not in self.config:
            print("No databaseURL provided, skipping accessibility checks")
            return
        
        database_url = self.config['databaseURL']
        
        print(f"\nChecking database general accessibility")
        
        # Common Firebase database endpoints to check
        endpoints = [
            "/.json",
            "/Users.json",
            "/users.json",
            "/Logs.json",
            "/logs.json",
            "/Messages.json",
            "/messages.json",
            "/Posts.json",
            "/posts.json",
            "/Comments.json",
            "/comments.json",
            "/Profiles.json",
            "/profiles.json",
            "/Settings.json",
            "/settings.json",
            "/Config.json",
            "/config.json"
        ]
        
        # Test anonymous, authenticated legacy (Bearer), and modern (Firebase)
        headers_list = [{}]
        if self.id_token:
            headers_list.append({"Authorization": f"Bearer {self.id_token}"})
            headers_list.append({"Authorization": f"Firebase {self.id_token}"})
        
        for i, headers in enumerate(headers_list):
            if not headers:
                auth_type = "anonymous"
            elif "Bearer" in headers.get("Authorization", ""):
                auth_type = "authenticated (Bearer)"
            else:
                auth_type = "authenticated (Firebase)"
            accessible_endpoints = []
            
            for endpoint in endpoints:
                url = f"{database_url}{endpoint}"
                curl_cmd = f"curl '{url}'"
                if headers:
                    curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
                
                try:
                    response = requests.get(url, headers=headers, timeout=5)
                    if response.status_code == 200:
                        accessible_endpoints.append(endpoint)
                        print(f"✓ Database endpoint accessible ({auth_type}): {endpoint}")
                        
                        # Save data if it contains content
                        try:
                            data = response.json()
                            if data:  # Only save if there's actual data
                                filename = f"database-{endpoint.replace('/', '').replace('.json', '')}-{auth_type.replace(' ', '-').replace('(', '').replace(')', '')}.json"
                                with open(filename, 'w') as f:
                                    json.dump(data, f, indent=2)
                                print(f"  Data saved to {filename}")
                        except Exception as e:
                            print(f"  Could not parse/save data: {e}")
                    elif response.status_code == 401:
                        print(f"✗ Database endpoint requires auth ({auth_type}): {endpoint}")
                    elif response.status_code == 404:
                        # Don't print for 404s as this is expected for non-existent paths
                        pass
                    else:
                        print(f"- Database endpoint status {response.status_code} ({auth_type}): {endpoint}")
                except requests.exceptions.Timeout:
                    print(f"- Database endpoint timeout ({auth_type}): {endpoint}")
                except Exception as e:
                    # Silently skip connection errors for non-existent endpoints
                    pass
            
            if accessible_endpoints:
                print(f"\nSummary ({auth_type}): Found {len(accessible_endpoints)} accessible endpoints")
            else:
                print(f"\nSummary ({auth_type}): No accessible endpoints found")
    
    def check_database_url(self):
        """Check if databaseURL is accessible and writable"""
        if 'databaseURL' not in self.config:
            print("No databaseURL provided, skipping database checks")
            return
        
        database_url = self.config['databaseURL']
        poc_data = {"poc": self.random_string}
        
        print(f"\nChecking database URL: {database_url}")
        
        # Test anonymous, authenticated legacy (Bearer), and modern (Firebase)
        headers_list = [{}]
        if self.id_token:
            headers_list.append({"Authorization": f"Bearer {self.id_token}"})
            headers_list.append({"Authorization": f"Firebase {self.id_token}"})
        
        for i, headers in enumerate(headers_list):
            if not headers:
                auth_type = "anonymous"
            elif "Bearer" in headers.get("Authorization", ""):
                auth_type = "authenticated (Bearer)"
            else:
                auth_type = "authenticated (Firebase)"
            
            # Test with /o/ directory - PUT
            write_url = f"{database_url}/o/poc_{self.random_string}.json"
            curl_cmd = f"curl '{write_url}' -XPUT -d '{json.dumps(poc_data)}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Attempting database PUT with /o/ ({auth_type})", curl_cmd)
            
            try:
                response = requests.put(write_url, headers=headers, json=poc_data)
                if response.status_code == 200:
                    print(f"✓ Database PUT successful with /o/ ({auth_type})")
                    
                    # Verify write
                    verify_response = requests.get(write_url, headers=headers)
                    if verify_response.status_code == 200:
                        print(f"✓ Database PUT verified ({auth_type})")
                        print(f"  URL: {write_url}")
                else:
                    print(f"✗ Database PUT failed with /o/ ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Database PUT error with /o/ ({auth_type}): {e}")
            
            # Test with /o/ directory - POST
            post_url = f"{database_url}/o/poc_{self.random_string}_post.json"
            curl_cmd = f"curl '{post_url}' -XPOST -d '{json.dumps(poc_data)}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Attempting database POST with /o/ ({auth_type})", curl_cmd)
            
            try:
                response = requests.post(post_url, headers=headers, json=poc_data)
                if response.status_code == 200:
                    print(f"✓ Database POST successful with /o/ ({auth_type})")
                    # POST usually returns the new key/ID
                    try:
                        result = response.json()
                        print(f"  Created with ID: {result}")
                    except:
                        pass
                else:
                    print(f"✗ Database POST failed with /o/ ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Database POST error with /o/ ({auth_type}): {e}")
            
            # Test direct write - PUT
            direct_put_url = f"{database_url}/poc_{self.random_string}.json"
            curl_cmd = f"curl '{direct_put_url}' -XPUT -d '{json.dumps(poc_data)}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Attempting direct database PUT ({auth_type})", curl_cmd)
            
            try:
                response = requests.put(direct_put_url, headers=headers, json=poc_data)
                if response.status_code == 200:
                    print(f"✓ Direct database PUT successful ({auth_type})")
                    
                    # Verify write
                    verify_response = requests.get(direct_put_url, headers=headers)
                    if verify_response.status_code == 200:
                        print(f"✓ Direct database PUT verified ({auth_type})")
                        print(f"  URL: {direct_put_url}")
                else:
                    print(f"✗ Direct database PUT failed ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Direct database PUT error ({auth_type}): {e}")
            
            # Test direct write - POST
            direct_post_url = f"{database_url}/poc_{self.random_string}_post.json"
            curl_cmd = f"curl '{direct_post_url}' -XPOST -d '{json.dumps(poc_data)}'"
            if headers:
                curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
            self._print_debug(f"Attempting direct database POST ({auth_type})", curl_cmd)
            
            try:
                response = requests.post(direct_post_url, headers=headers, json=poc_data)
                if response.status_code == 200:
                    print(f"✓ Direct database POST successful ({auth_type})")
                    # POST usually returns the new key/ID
                    try:
                        result = response.json()
                        print(f"  Created with ID: {result}")
                    except:
                        pass
                else:
                    print(f"✗ Direct database POST failed ({auth_type}, status: {response.status_code})")
            except Exception as e:
                print(f"✗ Direct database POST error ({auth_type}): {e}")
    
    def check_remote_config(self):
        """Check if remote config is accessible"""
        if 'apiKey' not in self.config or 'messagingSenderId' not in self.config or 'appId' not in self.config:
            print("Missing required fields for remote config check (apiKey, messagingSenderId, appId)")
            return
        
        print(f"\nChecking remote config access")
        
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{self.config['messagingSenderId']}/namespaces/firebase:fetch?key={self.config['apiKey']}"
        headers = {'Content-Type': 'application/json'}
        data = {
            "appId": self.config['appId'],
            "appInstanceId": "PROD"
        }
        
        curl_cmd = f"curl -X POST '{url}' -H 'Content-Type: application/json' --data '{json.dumps(data)}'"
        self._print_debug(f"Checking remote config", curl_cmd)
        
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                result = response.json()
                if 'entries' in result:
                    print(f"✓ Remote config accessible")
                    with open('remoteconfig.json', 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"  Config saved to remoteconfig.json")
                elif result.get('state') == 'NO_TEMPLATE':
                    print(f"- Remote config: No template configured")
                else:
                    print(f"✗ Remote config check: Unknown response")
            else:
                print(f"✗ Remote config check failed (status: {response.status_code})")
        except Exception as e:
            print(f"✗ Remote config check error: {e}")
    
    def check_crashlytics(self):
        """Check for Crashlytics data access (additional check)"""
        if 'appId' not in self.config or 'apiKey' not in self.config:
            print("Missing required fields for Crashlytics check")
            return
        
        print(f"\nChecking Crashlytics access")
        
        url = f"https://firebasecrashlytics.googleapis.com/v1/projects/{self.config.get('projectId', 'unknown')}/apps/{self.config['appId']}/issues"
        headers = {'X-Goog-Api-Key': self.config['apiKey']}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                print(f"✓ Crashlytics data accessible")
            else:
                print(f"✗ Crashlytics not accessible (status: {response.status_code})")
        except Exception as e:
            print(f"✗ Crashlytics check error: {e}")
    
    def check_firestore_collections(self):
        """Check for accessible Firestore collections"""
        if 'projectId' not in self.config:
            print("No projectId provided, skipping Firestore collection checks")
            return
        
        project_id = self.config['projectId']
        
        print(f"\nChecking Firestore collections accessibility")
        
        # Common collection names to check
        collections = [
            "users", "Users", "log", "Log", "logs", "Logs",
            "upload", "Upload", "uploads", "Uploads", "images", "Images",
            "files", "Files", "settings", "Settings", "messages", "Messages",
            "config", "Config"
        ]
        
        # Test anonymous, authenticated legacy (Bearer), and modern (Firebase)
        headers_list = [{}]
        if self.id_token:
            headers_list.append({"Authorization": f"Bearer {self.id_token}"})
            headers_list.append({"Authorization": f"Firebase {self.id_token}"})
        
        for i, headers in enumerate(headers_list):
            if not headers:
                auth_type = "anonymous"
            elif "Bearer" in headers.get("Authorization", ""):
                auth_type = "authenticated (Bearer)"
            else:
                auth_type = "authenticated (Firebase)"
            accessible_collections = []
            
            for collection in collections:
                url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection}"
                curl_cmd = f"curl '{url}'"
                if headers:
                    curl_cmd += f" -H 'Authorization: {headers['Authorization']}'"
                
                try:
                    response = requests.get(url, headers=headers, timeout=10)
                    if response.status_code == 200:
                        accessible_collections.append(collection)
                        print(f"✓ Firestore collection accessible ({auth_type}): {collection}")
                        
                        # Save collection data if it contains content
                        try:
                            data = response.json()
                            if data and 'documents' in data:  # Only save if there are documents
                                filename = f"firestore-{collection}-{auth_type.replace(' ', '-').replace('(', '').replace(')', '')}.json"
                                with open(filename, 'w') as f:
                                    json.dump(data, f, indent=2)
                                print(f"  Collection data saved to {filename}")
                        except Exception as e:
                            print(f"  Could not parse/save collection data: {e}")
                    elif response.status_code == 401:
                        print(f"✗ Firestore collection requires auth ({auth_type}): {collection}")
                    elif response.status_code == 403:
                        print(f"✗ Firestore collection access denied ({auth_type}): {collection}")
                    elif response.status_code == 404:
                        # Don't print for 404s as this is expected for non-existent collections
                        pass
                    else:
                        print(f"- Firestore collection status {response.status_code} ({auth_type}): {collection}")
                except requests.exceptions.Timeout:
                    print(f"- Firestore collection timeout ({auth_type}): {collection}")
                except Exception as e:
                    # Silently skip connection errors for non-existent collections
                    pass
            
            if accessible_collections:
                print(f"\nFirestore Summary ({auth_type}): Found {len(accessible_collections)} accessible collections")
            else:
                print(f"\nFirestore Summary ({auth_type}): No accessible collections found")
    
    def run_all_checks(self, email: str, password: str):
        """Run all security checks"""
        print(f"Starting Firebase configuration security tests...\n")
        print(f"Configuration fields found: {', '.join(self.config.keys())}\n")
        
        # Check 1: Registration
        self.check_registration(email, password)
        
        # Check 2: Storage bucket access
        self.check_storage_bucket()
        
        # Check 3: Storage upload
        self.check_storage_upload()
        
        # Check 4: Database URL
        self.check_database_url()
        
        # Check 4.5: Database general accessibility
        self.check_database_accessibility()
        
        # Check 5: Remote config
        self.check_remote_config()
        
        # Check 6: Firestore collections
        self.check_firestore_collections()
        
        # Additional checks
        self.check_crashlytics()
        
        print(f"\nAll checks completed!")


def parse_firebase_config(config_string: str) -> Dict[str, str]:
    """Parse Firebase configuration from various formats"""
    # Strip any leading/trailing whitespace
    config_string = config_string.strip()
    
    # First try to parse as valid JSON directly
    try:
        config = json.loads(config_string)
        return config
    except json.JSONDecodeError:
        pass
    
    # Remove comments and clean up the string
    lines = []
    for line in config_string.split('\n'):
        # Remove comments
        line = re.sub(r'//.*$', '', line)
        line = re.sub(r'/\*.*?\*/', '', line)
        lines.append(line)
    config_string = '\n'.join(lines)
    
    # Try to convert JavaScript object notation to valid JSON
    # This handles multiple formats: unquoted keys, single quotes, etc.
    try:
        # Handle cases where the object might not be wrapped in braces
        if not config_string.strip().startswith('{'):
            config_string = '{' + config_string + '}'
        
        # Step 1: Handle unquoted keys (convert to quoted keys)
        # Match unquoted keys more carefully - only at the beginning of lines or after commas/braces
        # This regex looks for word characters that are followed by optional whitespace and a colon,
        # but only when they're at the start of a line (after whitespace) or after { or ,
        config_string = re.sub(r'(^|\s|[{,])\s*(\w+)(\s*):', r'\1"\2"\3:', config_string, flags=re.MULTILINE)
        
        # Step 2: Replace single quotes with double quotes for string values
        # Be more careful - only replace single quotes that surround complete values
        config_string = re.sub(r":\s*'([^']*)'", r': "\1"', config_string)
        
        # Step 3: Remove trailing commas before closing braces/brackets
        config_string = re.sub(r',(\s*[}\]])', r'\1', config_string)
        
        # Try to parse as JSON
        config = json.loads(config_string)
        return config
        
    except json.JSONDecodeError as e:
        # If JSON conversion fails, fall back to regex parsing
        pass
    
    # Fallback: Extract key-value pairs using a more sophisticated line-by-line approach
    config = {}
    
    for line in config_string.split('\n'):
        line = line.strip()
        # Skip empty lines, comments, and braces
        if not line or line.startswith('#') or line.startswith('//') or line in ['{', '}', ',']:
            continue
        
        # Remove trailing comma if present
        line = line.rstrip(',')
        
        # Find the key-value separator (first colon not inside quotes)
        if ':' not in line:
            continue
        
        # Parse the line character by character to find the key-value separator
        key_end = -1
        in_quotes = False
        quote_char = None
        
        for i, char in enumerate(line):
            if char in ['"', "'"] and (i == 0 or line[i-1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None
            elif char == ':' and not in_quotes:
                key_end = i
                break
        
        if key_end == -1:
            continue
            
        # Extract key and value parts
        key_part = line[:key_end]
        value_part = line[key_end + 1:]
        
        # Clean up the key (remove quotes and whitespace)
        key = key_part.strip().strip('\'"')
        
        # Clean up the value - handle quoted strings properly
        value = value_part.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            # Properly quoted value - remove the outer quotes
            value = value[1:-1]
        
        # Store the key-value pair
        if key:
            config[key] = value
    
    if config:
        return config
    
    # If all attempts fail, raise an error
    raise ValueError("Unable to parse Firebase configuration. Please check the format.\n"
                   "Supported formats:\n"
                   '- JSON: {"apiKey":"value","authDomain":"value"}\n'
                   "- Unquoted keys: {apiKey:'value',authDomain:'value'}\n"
                   "- Mixed quotes: {apiKey:\"value\",authDomain:'value'}\n"
                   "- Multiline with whitespace")


def main():
    parser = argparse.ArgumentParser(description='Test Firebase configurations for security misconfigurations')
    
    # Configuration input methods
    parser.add_argument('--firebase-config', type=str, help='Firebase config as JSON string')
    parser.add_argument('--api-key', type=str, help='Firebase API key')
    parser.add_argument('--auth-domain', type=str, help='Firebase auth domain')
    parser.add_argument('--database-url', type=str, help='Firebase database URL')
    parser.add_argument('--project-id', type=str, help='Firebase project ID')
    parser.add_argument('--storage-bucket', type=str, help='Firebase storage bucket')
    parser.add_argument('--sender-id', type=str, help='Firebase messaging sender ID')
    parser.add_argument('--app-id', type=str, help='Firebase app ID')
    parser.add_argument('--measurement-id', type=str, help='Firebase measurement ID')
    
    # Test options
    parser.add_argument('--email', type=str, default='test@bugbounty.com', help='Email for registration test')
    parser.add_argument('--password', type=str, default='TestPassword123!', help='Password for registration test')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output with curl commands')
    
    args = parser.parse_args()
    
    # Build configuration dictionary
    config = {}
    
    if args.firebase_config:
        try:
            print(f"Parsing Firebase configuration...")
            if args.debug:
                print(f"Original config: {args.firebase_config}")
            
            config = parse_firebase_config(args.firebase_config)
            
            if args.debug:
                print(f"Parsed config: {json.dumps(config, indent=2)}")
        except Exception as e:
            print(f"Error parsing Firebase config: {e}")
            sys.exit(1)
    
    # Override with individual arguments if provided
    if args.api_key:
        config['apiKey'] = args.api_key
    if args.auth_domain:
        config['authDomain'] = args.auth_domain
    if args.database_url:
        config['databaseURL'] = args.database_url
    if args.project_id:
        config['projectId'] = args.project_id
    if args.storage_bucket:
        config['storageBucket'] = args.storage_bucket
    if args.sender_id:
        config['messagingSenderId'] = args.sender_id
    if args.app_id:
        config['appId'] = args.app_id
    if args.measurement_id:
        config['measurementId'] = args.measurement_id
    
    if not config:
        print("No Firebase configuration provided!")
        parser.print_help()
        sys.exit(1)
    
    # Create tester and run checks
    tester = FirebaseConfigTester(config, debug=args.debug)
    tester.run_all_checks(args.email, args.password)


if __name__ == '__main__':
    main()