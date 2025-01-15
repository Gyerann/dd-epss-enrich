Dependecies:  
docker  
defectdojo image  
jsonq golang package (github.com/jmoiron/jsonq)  
  
Use from terminal with flags:  
-t Authorization token  
-i IP address (Defaults to localhost)  
-p Port (Defaults to 8080)  
  
The script will get all the active findings from DefectDojo, get the latest EPSS data  
and update epss_score and epss_percentile fields based on CVE numbers.  
It then sends patch requests through the DefectDojo API.  