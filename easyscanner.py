import os
import hashlib
import requests
import json
from datetime import datetime
from pathlib import Path
from time import sleep

class EasyScanner:
    def __init__(self, api_key):
       ## parsing the virustotal api through the api link
        self.api_key = api_key
        self.headers = {'x-apikey': api_key}
        self.nistHashes = set()
        self.vt_base_url = 'https://www.virustotal.com/api/v3'

    def loadNist(self, database_path):
        ## Loading hashes from NIST database.
        try:
            with open(database_path, 'r') as file:
                for line in file:
                    hash_value = line.strip().split(',')[0]
                    self.nistHashes.add(hash_value)
            print(f"✅ Loaded {len(self.nistHashes)} NIST hashes")
        except FileNotFoundError:
            print("❌ NIST db file not added. Please add it and try again!")
            return False
        return True

    def getHash(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                return hashlib.md5(file.read()).hexdigest()
        except Exception as e:
            print(f"❌ Error parsing the hashes for {file_path}: {e}")
            return None

    def getResults(self, analysis_id, max_retries=10):
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    f'{self.vt_base_url}/analyses/{analysis_id}',
                    headers=self.headers
                )
                response.raise_for_status()
                analysis = response.json()
                
                if analysis['data']['attributes']['status'] == 'completed':
                    results = analysis['data']['attributes']
                    stats = results['stats']
                    engines = results.get('results', {})
                    
                    ## parse results from detection scanners
                    detections = []
                    for engine, result in engines.items():
                        if result.get('category') == 'malicious':
                            detections.append({
                                'engine': engine,
                                'result': result.get('result', 'unknown')
                            })
                    
                    return {
                        'status': 'completed',
                        'malicious_count': stats['malicious'],
                        'total_engines': stats['malicious'] + stats['undetected'],
                        'detection_rate': (stats['malicious'] / (stats['malicious'] + stats['undetected'])) * 100,
                        'detections': detections
                    }
                ## if failed, retry after 20 seconds of sleep + max tries of 10 till timeout
                print(f"⏳ Scanning... (Attempt {attempt + 1}/{max_retries})")
                sleep(20)
                
            except Exception as e:
                print(f"⚠️ Error, Please try again (Attempt {attempt + 1}): {str(e)}")
                sleep(10)
        
        return {'status': 'timeout', 'error': 'timeout, please try again'}

    def scanFile(self, file_path):
        ## scan file by file (NIST + VT) ##
        file_path = Path(file_path)
        print(f"\n🔍 Scanning: {file_path.name}")
        
        result = {
            'file_name': file_path.name,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'unknown',
            'details': {}
        }

        # gethash from file
        fileHash = self.getHash(file_path)
        if not fileHash:
            return result

        # check database
        if fileHash in self.nistHashes:
            result['status'] = 'safe'
            result['details'] = {'source': 'NIST database', 'confidence': 'high'}
            print(f"✅ File hash is safe (NIST database)")
            return result

        # now upload to VirusTotal
        try:
            print("📤 Uploading to VirusTotal...")
            files = {'file': open(file_path, 'rb')}
            response = requests.post(
                f'{self.vt_base_url}/files',
                headers=self.headers,
                files=files
            )
            response.raise_for_status()
            analysis_id = response.json()['data']['id']
            
            print("⏳ Loading results...")
            vt_results = self.getResults(analysis_id)
            
            if vt_results['status'] == 'completed':
                result['status'] = 'malicious' if vt_results['malicious_count'] > 0 else 'safe'
                result['details'] = {
                    'source': 'VirusTotal',
                    'malicious_detections': vt_results['malicious_count'],
                    'total_scanners': vt_results['total_engines'],
                    'detection_rate': round(vt_results['detection_rate'], 2),
                    'detection_details': vt_results['detections']
                }
                
                # printing results
                
                if result['status'] == 'malicious':
                    print(f"⚠️ MALICIOUS FILE DETECTED! DO NOT RUN IT")
                    print(f"📊 Malicious Rate: {vt_results['detection_rate']:.1f}%")
                    print(f"🔍 Detected by {vt_results['malicious_count']} out of {vt_results['total_engines']} engine scanners")
                    if vt_results['detections']:
                        print("\nDetections by antivirus engines:")
                        for det in vt_results['detections'][:10]:  # Show top 10 detections
                            print(f"  • {det['engine']}: {det['result']}")
                else:
                    print(f"✅ SAFE (VirusTotal)")
                    print(f"📊 Scanned by {vt_results['total_engines']} VirusTotal engines")
            
        except Exception as e:
            result['status'] = 'error'
            result['details'] = {'error': str(e)}
            print(f"❌ Please try again: {str(e)}")

        return result

    def scanDirectory(self, directory_path):
        results = []
        directory = Path(directory_path)
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                result = self.scanFile(str(file_path))
                results.append(result)
                print("-" * 50)
                
        return results

    def saveReport(self, results, outputPath='.'):
        ## saving output results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        reportPath = Path(outputPath) / f'{timestamp}.json'
        
        with open(reportPath, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📝 Output saved to: {reportPath}")

def main():
    # your VirusTotal API key here
    API_KEY = 'API_KEY'

    scanner = EasyScanner(API_KEY)

    if not scanner.loadNist('NSRLFile.txt'):
        return

	# path to scan
    dirToScan = Path('/home/')
    
    print(f"\n🔎 Scanning {dirToScan}")
    results = scanner.scanDirectory(dirToScan)
    
    scanner.saveReport(results)

if __name__ == '__main__':
    main()
