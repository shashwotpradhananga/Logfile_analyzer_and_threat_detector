#This is an updataed version of logfile analyzer and threat detector as it alerts the user only if there are 5 or more failed login attempts from same ip address
#within 2 minutes.

from datetime import datetime, timedelta


failed_logins = {}

THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=2)


with open("sample.log", "r") as file:

    for line in file:

        line = line.strip()

        parts = line.split(",")

        timestamp = parts[0]
        username = parts[1]
        event = parts[2]
        ip_address = parts[3]

        # Convert the timestamp from text into a datetime object
        login_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        if event == "LOGIN_FAILED":

            # Create a list for this IP if it doesn't exist
            if ip_address not in failed_logins:
                failed_logins[ip_address] = []

            # Add the current failed login time
            failed_logins[ip_address].append(login_time)


print("\nFailed login attempts:")

for ip, times in failed_logins.items():

    print(ip, ":", len(times))


print("\nThreat detection:")

for ip, times in failed_logins.items():

    # Check every failed login as the beginning of a possible
    # 2-minute window
    for i in range(len(times)):

        window_start = times[i]
        window_end = window_start + TIME_WINDOW

        count = 0

        # Count how many failed logins occurred in this window
        for login_time in times:

            if window_start <= login_time <= window_end:
                count += 1

        if count >= THRESHOLD:

            print(
                "ALERT: Possible brute-force activity from",
                ip,
                "-",
                count,
                "failed logins within 2 minutes"
            )

            break
