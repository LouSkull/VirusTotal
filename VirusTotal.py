import requests,os,time,base64


APII = (base64.b64decode('NmI4NjNjZjU4YTZlZGU5MDQzZGYzMjFkNTU4ZDA5NzRkM2UxNjgwZTcyMmVlNzM5OTYzMTcxZmIwMDBkZmJiMg==').decode('utf-8'))


os.system("title VIRUSTOTAL")
os.system("color 80")
os.system("cls")

print("OFFICIAL SITE: https://www.virustotal.com")
print(
f"""
        _                 __        __        __                  _ __  __          __  
 _   __(_)______  _______/ /_____  / /_____ _/ /           ____ _(_) /_/ /_  __  __/ /_ 
| | / / / ___/ / / / ___/ __/ __ \/ __/ __ `/ /  ______   / __ `/ / __/ __ \/ / / / __ \\
| |/ / / /  / /_/ (__  ) /_/ /_/ / /_/ /_/ / /  /_____/  / /_/ / / /_/ / / / /_/ / /_/ /
|___/_/_/   \__,_/____/\__/\____/\__/\__,_/_/            \__, /_/\__/_/ /_/\__,_/_.___/ 
                                                        /____/                          
"""
)

def scan_file(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, files=files, params=params)

    return response.json()

def check_report(api_key, resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)

    return response.json()

def main():
    api_key = APII
    
    file_path = input("Enter the path to the file: ")

    scan_result = scan_file(api_key, file_path)

    resource = scan_result.get('resource')
    if resource:
        report = check_report(api_key, resource)
        
        if report.get('response_code') == 1:
            print("\nScan Report:")
            print("Scan Date:", report.get('scan_date'))
            print("File Name:", report.get('verbose_msg'))
            
            positives = report.get('positives')
            total = report.get('total')
            
            if positives is not None and total is not None:
                print("Detection Ratio: {}/{}".format(positives, total))
                
                if positives > 0:
                    print("Detections:")
                    for antivirus, result in report.get('scans').items():
                        if result.get('detected'):
                            print("{}: {}".format(antivirus, result.get('result')))
                    input("\nPress Enter to continue...")
                else:
                    print("No detections.")
                    input("\nPress Enter to continue...")
            else:
                print("Detection information not available.")
                input("\nPress Enter to continue...")
        else:
            print("Error in retrieving the scan report. Please try again later.")
            input("\nPress Enter to continue...")
    else:
        print("Error in submitting the file for scanning. Please try again later.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
