import sys, requests, json, time, urllib.request

def checkURL(target):
    try:
        status = urllib.request.urlopen(target).code
        return True
    except Exception as err: 
        print("!!! URL not found, please try again !!!")
        return False

#Scan URL
#輸入格式: python3 zap_api_scan.py http://testphp.vulnweb.com
target = sys.argv[1] 
#target = "https://localhost:8080/" #For test URL
#target = "http://testphp.vulnweb.com/" #For test URL
#target = "http://q90eujqowjdjaskdaskd/" #For test the wrong URL

#Open file
path = 'ZAP_output.txt'
file = open ( path, 'w')

file.write ( '-----------------Start scan-----------------\n')
file.write ( '-- Target: ' + target + '\n')
print ( '-----------------Start scan-----------------')
print ( '-- Target: ' + target)

#Check the URL can be find
urlCanFind = checkURL(target)
if urlCanFind == False:
    sys.exit()

#Start spider
r = requests.get ( "http://localhost:8080/JSON/spider/action/scan/?apikey=jrninaaisk2pc2vnb9vtistvd8&url="+ target +"&maxChildren=&recurse=&contextName=&subtreeOnly=")
scanId = json.loads(r.text)["scan"]
#print ( scanId)

file.write ( "\n----------- ZAP Start Spider Scan -----------\n")
print ( "\n----------- ZAP Start Spider Scan -----------")

#Check spider scan
scanNotComplete = True
while (scanNotComplete == True):
    r = requests.get("http://localhost:8080/JSON/spider/view/status/?apikey=jrninaaisk2pc2vnb9vtistvd8&scanId=" + scanId)
    scanPercent = json.loads(r.text)["status"]

    if ( int (scanPercent) < 100):
        file.write ( "-- ZAP Spider Scan " + scanPercent + "%\n")
        print ( "-- ZAP Spider Scan " + scanPercent + "%")
        time.sleep(1)
    else:
        scanNotComplete = False
        file.write ( "-- ZAP Spider Scan " + scanPercent + "% completed\n\n")
        print ( "-- ZAP Spider Scan " + scanPercent + "% completed\n")

#Collect URLs
r = requests.get ( "http://localhost:8080/JSON/core/view/urls/?apikey=jrninaaisk2pc2vnb9vtistvd8&baseurl="+ target)
urls = json.loads(r.text)["urls"]

for url in urls:
    file.write ( '++ '+url + '\n')
    print ( '++ '+url)

#Collect alert
r = requests.get ( "http://localhost:8080/JSON/core/view/alerts/?apikey=jrninaaisk2pc2vnb9vtistvd8&baseurl=" + target + "&start=&count=&riskId=")

list = []
list = json.loads(r.text)["alerts"]

file.write ( "\n-------------------alert-------------------\n")
print ( "\n-------------------alert-------------------")

for alist in list:

    file.write ( "-- SourceID: " + alist["sourceid"] + '\n')
    file.write ( "-- URL: " + alist["url"] + '\n')
    file.write ( "-- Risk: " + alist["risk"] + '\n')
    file.write ( "-- Confidence: " + alist["confidence"] + '\n')
    file.write ( "-- CWEId: " + alist["cweid"] + '\n')
    file.write ( "-- WASCId: " + alist["wascid"] + '\n')
    file.write ( "-------------end of this alert-------------\n\n")

    print ( "-- SourceID: " + alist["sourceid"])
    print ( "-- URL: " + alist["url"])
    print ( "-- Risk: " + alist["risk"])
    print ( "-- Confidence: " + alist["confidence"])
    print ( "-- CWEId: " + alist["cweid"])
    print ( "-- WASCId: " + alist["wascid"])
    print ( "-------------end of this alert-------------\n")

#Report
'''
r = requests.get ( "http://localhost:8080/JSON/reports/action/generate/?apikey=jrninaaisk2pc2vnb9vtistvd8&title=FirstReport&template=traditional-html&theme=&description=&contexts=&sites=&sections=&includedConfidences=&includedRisks=&reportFileName=&reportFileNamePattern=&reportDir=&display=")
print ("-- Your report: " + json.loads(r.text)["generate"])
'''

file.write ( "--------------end of all scan--------------")
print ( "--------------end of all scan--------------")