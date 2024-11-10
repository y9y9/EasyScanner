# EasyScanner
## EasyScanner is a simple script that scans for malicious files in a specified directory using NIST NSRL and VirusTotal API.

### The tool will first calculate the md5 of a file and check hashes within the NIST Database and then it will upload it to VirusTotal for further analysis.

## How to run:
- first make sure you have the requirements ```pip install -r requirements.txt``` (most likely you will have everything installed by default)
- go to line 173 and add your API key
- go to line 177 and put in the path of your NIST hashes (unless its in same folder)
- got to line 181 and add the path you want to run the scans on, if you are stuck on this and need a NIST Hashset [click here](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/about-nsrl)

