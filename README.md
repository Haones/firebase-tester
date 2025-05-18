# Firebase Configuration Security Testing Tool

A Python tool for testing Firebase configurations for potential security misconfigurations.
The reason I decided to create separate tool is because other tools performs only specific checks and I want just to feed a single line with found config to make all checks.
Main goal of this tool is to cover all checks and put them together. If you know other checks feel free to create issue and I'll see if they can be added too.

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Setup Instructions

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/haones/firebase-tester
   cd firebase-tester
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python3 -m venv venv
   
   # On Linux/Mac:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install required dependencies**
   ```bash
   pip install requests>=2.28.0
   ```

4. **Make the script executable (optional, Linux/Mac only)**
   ```bash
   chmod +x fb_tester.py
   ```

## Quick Start

### Basic Usage

Test with a complete Firebase configuration:
```bash
python3 fb_tester.py --firebase-config '{"apiKey":"AIza...","authDomain":"project.firebaseapp.com","projectId":"project-prd","storageBucket":"project.appspot.com"}'
```

Test with individual parameters:
```bash
python3 fb_tester.py --api-key "AIza..." --project-id "project-prd" --storage-bucket "project.appspot.com"
```

### Advanced Usage

Enable debug mode to see curl commands:
```bash
python3 fb_tester.py --firebase-config '...' --debug
```

Use custom credentials for registration test:
```bash
python3 fb_tester.py --firebase-config '...' --email "test@example.com" --password "SecurePass123!"
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--firebase-config` | Complete Firebase config as JSON string |
| `--api-key` | Firebase API key |
| `--auth-domain` | Firebase auth domain |
| `--database-url` | Firebase database URL |
| `--project-id` | Firebase project ID |
| `--storage-bucket` | Firebase storage bucket |
| `--sender-id` | Firebase messaging sender ID |
| `--app-id` | Firebase app ID |
| `--measurement-id` | Firebase measurement ID |
| `--email` | Email for registration test (default: test@bugbounty.com) |
| `--password` | Password for registration test (default: TestPassword123!) |
| `-d, --debug` | Enable debug output with curl commands |

## Security Checks Performed

1. **User Registration** - Tests if new user registration is allowed with the API key
2. **Storage Bucket Access** - Checks accessibility of Firebase Storage and Google Cloud Storage
3. **Storage Upload** - Tests file upload capabilities (both authenticated and anonymous)
4. **Database Access** - Tests read/write access to Firebase Realtime Database
5. **Remote Config** - Attempts to fetch remote configuration data
6. **Crashlytics** - Checks for access to crash reporting data

## Output

The tool provides clear status indicators for each check:
- ✓ - Check passed (potential vulnerability)
- ✗ - Check failed (secure)
- - - Check skipped (missing required configuration)

## Examples

### Testing a minimal configuration
```bash
python3 fb_tester.py --api-key "AIzaSyAbc123..." --project-id "my-project"
```

### Testing with a config file
```bash
# Save your config to a file
echo '{"apiKey":"AIza...","projectId":"project-prd"}' > config.json

# Use it with the tool
python3 fb_tester.py --firebase-config "$(cat config.json)"
```

### Debug mode for manual verification
```bash
python3 fb_tester.py --firebase-config '...' -d > debug_output.txt
```

## Thanks
https://blog.securitybreached.org/2020/02/04/exploiting-insecure-firebase-database-bugbounty/ @MuhammadKhizerJaved
https://danangtriatmaja.medium.com/firebase-database-takover-b7929bbb62e1 @Danang Tri Atmaja

HackerOne reports:
https://hackerone.com/reports/684099
https://hackerone.com/reports/736283

## TO-DO
1. Check for FCM takeover and support AAAA keys: https://web.archive.org/web/20220921183800/https://abss.me/posts/fcm-takeover/?s=09
2. Check for accessible Cloud Firestore collections (try to guess) and ability to write: https://iosiro.com/blog/baserunner-exploiting-firebase-datastores

## Contributing

Feel free to add new security checks by:
1. Adding a new method to the `FirebaseConfigTester` class
2. Calling it from the `run_all_checks` method
3. Following the existing pattern for status reporting

## Disclaimer

This tool is for authorized security testing only. Always ensure you have permission before testing any Firebase configuration. The tool is provided as-is for educational purposes.