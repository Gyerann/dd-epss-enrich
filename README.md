Dependecies:  
docker  
defectdojo image  
  
  
TODO:  
	Finish enrich.go script:  
		Query EPSS data  
		Query all findings from defectdojo through API  
		Enrich all possible findings with EPSS data  
  
	Make an enrich.go container:  
		Runs enrich.go script  
		Waits for x hours / 1 day?  
		Create helm chart for easy deployment  
		Enrich container gets access token from DefectDojo container on startup  
  
	Backup mechanism:  
		Backup database every day  
  
	Testing:  
		Create test env with easy deployment  
		Create tests for enrich.go  
		
