#first lets understand the meaning of log, so log is basically a file that keeps track of activities/events of  computer, servers, applications and firewalls.
# now the function of log analyser is to go into that log file and check the activites done by the server or computer.
# and then comes the role of threat detector, the threat detector alerts the user after seeing the analyzed    data from the log analyser.
# from belowe the code for log analyser and threat detector begins

with open("sample.log","r") as file:
    for line in file:
        print(line.strip())

failed_logins = {}

with open("sample.log", "r") as file:
    for line in file:
        line = line.strip()
        parts = line.split(",")
        timestamp = parts[0]
        username = parts[1]
        event = parts[2]
        ip_address = parts[3]

        if event == "LOGIN_FAILED":
            if ip_address not in failed_logins:
                failed_logins[ip_address] = 0

                failed_logins[ip_address] += 1
    print("\nFailed login attempts:")
    for ip, count in failed_logins.items():
        print(ip, " ", count)

THRESHOLD = 5

for ip, count in failed_logins.items():

    print(ip, " ", count)

    if count >= THRESHOLD:
        print("ALERT: Possible brute-force activity from", ip)
