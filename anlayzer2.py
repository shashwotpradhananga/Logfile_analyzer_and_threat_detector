
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
    print(ip, ":", count)


THRESHOLD = 5

print("\nThreat detection:")

for ip, count in failed_logins.items():

    if count >= THRESHOLD:
        print("ALERT: Possible brute-force activity from", ip)
        
