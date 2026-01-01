import re #for pattern recongition and manipulation 
from collections import defaultdict #for producing the default values
from datetime import datetime #for manipulating the date and time

log_file = "/var/log/auth.log" #where the authentication logs will be
failure_threshold = 10 #max amount of failure attempts
minutes_bewteen = 5 #max amount time between failed attempts in minutes
output_file = "suspicious_activity_report.txt" #where the output will be printed to

#the failure pattern will compile the time(year, month, date, hour, minute, second), sudo authentication fail, and user 
failure_pattern = re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}-\d{2}:\d{2}:\d{2}.*?) .* sudo: pam_unix\(sudo:auth\): authentication failure.*user=(?P<user>\w+)')

failures = defaultdict(list) #creates a dictionary for {user: timestamps of failed attempts}

with open(log_file, "r") as file: #opens the authentication file
	for line in file: #reads every line in the file
		match = failure_pattern.search(line) #checks if the line matches the failure_pattern
		if match:
			timestamp_str = match.group("timestamp") #the timestamp from the failure_pattern is declared here as timestamp_str
			user = match.group("user") #the user from the failure_pattern is declared here as user
			
			timestamp = datetime.fromisoformat(timestamp_str.split("-5:00")[0]) #converts the string into an object removing the timezone
			failures[user].append(timestamp) #adding the user and time to the dictionary
			
suspicious_users = {} #dictionary for users that triggers the authentication failure


for user, times in failures.items(): #looping through the user's timestamps of attempts
	times.sort() #sorts all the times to make easier when inspecting them
	
	for i in range(len(times)): #looping through the timestamps
		window = times[i:i + failure_threshold] #window is the amount of attempts that happened in 5 miuntes
		if len(window) >= failure_threshold: #checks if window attempts is more then 10
			delta = (window[-1] - window[0]).total_seconds() / 60 #finds the difference between the first and last attempt
			if delta <= minutes_between: #checks if attmepts happened 5 minutes
				suspicious_users[user] = window #adds the user and their attempts to the suspicious user dictionary
				break #stops looping when the user is flagged

with open(output_file, "w") as report: #opens the output_file to write to it
	if suspicious_users: #if suspicious_users is not an empty dictionary
		print("[!] Suspicious authentication activity detected\n") #prints this to the terminal
		report.wirte("Suspicious Authentication Activity Report\n") #write this to the output_file
		
		#prints a unique message for each user to the terminal and to the output_file
		for user, times in suspicious_users.items():
			message = f"User '{user}' exceed {failure_threshold} failures in {minutes_between} minutes.\n"
			print(message) 
			report.write(message)
	else: #if suspicious_users is an empty dictionary 
		print("No suspicious authentication activity detected.")
		report.write("No suspicious authentication activity detected.\n")
