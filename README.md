USER MANAGEMENT 


# Linux Labs

#### Lab Task Steps


#### Part 1: Setup and Verify Networking Configuration

1. **Check network interfaces:**
   - Run `ip addr` or `ifconfig` to identify your network interfaces. Typically, your interface may be `eth0`, `ens33`, `enp0s3`, etc.
   
2. **Verify connectivity:**
   - Make sure you can reach the internet and other machines in your local network:
     - `ping 8.8.8.8` (Google DNS server)
     - `ping <your_gateway_ip>`
     - `ping <another_machine_in_the_network>`
   
3. **Confirm that `iptables` is installed:**
   - Run `iptables --version` to ensure that `iptables` is installed. If not, install it:
     - `sudo apt install iptables` (on Ubuntu/Debian)
     - `sudo yum install iptables` (on CentOS/RHEL)



#### Part 2: Configure a Basic Firewall

1. **Set default policies:**
   - By default, we want to deny all incoming traffic and allow outgoing traffic. This can be set as follows:
   
   ```bash
   sudo iptables -P INPUT DROP      # Block all incoming traffic
   sudo iptables -P FORWARD DROP    # Block forwarding
   sudo iptables -P OUTPUT ACCEPT   # Allow all outgoing traffic
   ```

2. **Allow established connections:**
   - To maintain established connections (like active SSH sessions), you need to allow the related and established connections:
   
   ```bash
   sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   ```




3. **Allow SSH access (port 22):**
   - You need to allow SSH traffic to connect remotely to the system. This is done by allowing inbound traffic on port 22:
   
   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   ```

4. **Allow HTTP/HTTPS (ports 80, 443):**
   - If your server will serve web pages, open HTTP and HTTPS ports:
   
   ```bash
   sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # Allow HTTP
   sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # Allow HTTPS
   ```

5. **Allow ICMP (ping) requests:**
   - You can allow ICMP traffic for ping functionality:
   
   ```bash
   sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
   ```

6. **Save your rules:**
   - To ensure the firewall rules persist after reboot, save the iptables rules:
   
   ```bash
   sudo iptables-save > /etc/iptables/rules.v4   # For Debian/Ubuntu
   sudo service iptables save                    # For CentOS/RHEL
   ```








#### Part 3: Test Firewall Rules

1. **Test SSH connection:**
   - From another machine, try to SSH into your Linux server. It should work if port 22 is open.
   - `ssh user@<server-ip>`

2. **Test web server access (if applicable):**
   - If you allowed HTTP/HTTPS, try accessing the server from a browser:
     - `http://<server-ip>` for HTTP
     - `https://<server-ip>` for HTTPS (if SSL is configured)

3. **Test ping:**
   - From another machine, ping the server to ensure ICMP traffic is allowed.
     - `ping <server-ip>`

#### Part 4: Enhance Security (Optional)

1. **Block all incoming traffic by default, but allow specific IP ranges:**
   - You can restrict access to the server to specific IP ranges, for example:
   
   ```bash
   sudo iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT    # Allow local network
   sudo iptables -A INPUT -s <trusted-ip> -j ACCEPT        # Allow a specific trusted IP
   sudo iptables -A INPUT -j DROP                         # Block everything else
   ```

2. **Log dropped packets:**
   - You can enable logging to monitor dropped packets:
   
   ```bash
   sudo iptables -A INPUT -j LOG --log-prefix "Dropped Packet: "
   ```

3. **Rate limiting (Optional):**
   - To prevent brute-force attacks on services like SSH, you can limit the number of connections:
   
   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/minute -j ACCEPT
   ```

#### Part 5: Monitor and Manage Firewall

1. **View current firewall rules:**
   - Check the current rules using:
   
   ```bash
   sudo iptables -L
   ```

2. **Flush all rules (reset firewall):**
   - If you want to reset the firewall to its default state (deny all traffic):
   
   ```bash
   sudo iptables -F
   ```

3. **Delete a specific rule:**
   - If you need to delete a specific rule, use:
   
   ```bash
   sudo iptables -D INPUT -p tcp --dport 80 -j ACCEPT
   ```

### Lab Task Completion Criteria:
- You should have successfully set up the firewall with basic rules allowing SSH, HTTP/HTTPS, and ICMP while denying all other traffic.
- You should be able to test and verify that only the allowed traffic can reach the server.
- Bonus if you can configure logging or rate limiting.

Let me know if you need any specific instructions or configurations for your task!

#### Here's a detailed lab task focused on **port blocking**, **IP allowance**, **IP range configuration**, and **protocol allowance** using `iptables` for firewall management. This will help you learn how to manage network traffic based on ports, specific IP addresses, IP ranges, and protocols.

---

### **Lab Task: Configuring Port Blocking, IP Allowance, IP Range, and Protocol Allowance using `iptables`**

#### **Objective:**
- Block/allow specific ports.
- Permit traffic from specific IP addresses.
- Allow traffic only from certain IP ranges.
- Allow/deny specific network protocols.

---

### **Prerequisites:**
1. A Linux machine (Ubuntu, CentOS, or any distribution).
2. Administrative privileges (root or sudo).
3. Basic networking knowledge and the ability to use the terminal.

### **Steps for the Lab Task:**

---

### **1. Verify Current Networking and Firewall Configuration**

1. **Check IP addresses and network interfaces:**
   Run the following command to get a list of network interfaces and their IP addresses.
   ```bash
   ip addr
   ```

2. **Verify if `iptables` is installed:**
   Check if `iptables` is available on your system.
   ```bash
   iptables --version
   ```

3. **Check current `iptables` rules:**
   List all existing rules in the firewall.
   ```bash
   sudo iptables -L
   ```

---

### **2. Block Specific Ports**

You can block incoming traffic on specific ports using `iptables`.

1. **Block incoming traffic on port 80 (HTTP):**
   - This will block all HTTP traffic from reaching your server.
   ```bash
   sudo iptables -A INPUT -p tcp --dport 80 -j DROP
   ```

2. **Block incoming traffic on port 443 (HTTPS):**
   - This will block all HTTPS traffic.
   ```bash
   sudo iptables -A INPUT -p tcp --dport 443 -j DROP
   ```

3. **Verify the changes:**
   - List the rules to ensure that the ports are blocked.
   ```bash
   sudo iptables -L
   ```

4. **Test port blocking:**
   - From a different machine, try to access the blocked port using `curl` or a browser. 
   - You should not be able to reach the server on ports 80 or 443.

---

### **3. Allow Traffic from Specific IP Addresses**

You can allow or deny traffic based on specific IP addresses.

1. **Allow SSH (port 22) only from a specific IP address (e.g., `192.168.1.100`):**
   ```bash
   sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT
   ```

2. **Block SSH access from all other IP addresses:**
   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j DROP
   ```

3. **Verify the changes:**
   - List the rules again to confirm the changes.
   ```bash
   sudo iptables -L
   ```

4. **Test the configuration:**
   - Try to SSH into the server from `192.168.1.100` — it should work.
   - Try from any other IP — it should be blocked.

---

### **4. Allow Traffic from a Specific IP Range**

You can also allow traffic from a specific range of IPs. For example, if you want to allow access to your server from a range of IP addresses within the `192.168.1.0/24` subnet:

1. **Allow traffic from the IP range `192.168.1.0/24`:**
   ```bash
   sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT
   ```

2. **Block traffic from all other IP ranges:**
   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j DROP
   ```

3. **Verify the rules:**
   ```bash
   sudo iptables -L
   ```

4. **Test the configuration:**
   - Try accessing the server from an IP within the `192.168.1.0/24` range — it should work.
   - Try accessing from an outside range — it should be blocked.

---

### **5. Allow Specific Protocols (TCP, UDP, ICMP)**

You can allow or block specific network protocols (e.g., TCP, UDP, ICMP).

1. **Allow all incoming ICMP (Ping) requests:**
   ```bash
   sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
   ```

2. **Allow incoming UDP traffic on port 53 (DNS):**
   ```bash
   sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
   ```

3. **Allow incoming TCP traffic on port 22 (SSH):**
   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   ```

4. **Block UDP traffic:**
   - Block all UDP traffic.
   ```bash
   sudo iptables -A INPUT -p udp -j DROP
   ```

5. **Verify the changes:**
   List the rules again to ensure all protocols and ports are configured as needed.
   ```bash
   sudo iptables -L
   ```

6. **Test the configurations:**
   - Test ICMP by pinging the server.
   - Test UDP and TCP services using tools like `nc`, `ping`, or `curl` to ensure proper functionality.

---

### **6. Allow Specific IP and Port Combinations**

You can also allow specific combinations of IP and port.

1. **Allow traffic from `192.168.1.100` to port 22 (SSH):**
   ```bash
   sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT
   ```

2. **Allow traffic from `192.168.1.0/24` to port 80 (HTTP):**
   ```bash
   sudo iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 80 -j ACCEPT
   ```

3. **Block all other IP addresses from accessing port 80:**
   ```bash
   sudo iptables -A INPUT -p tcp --dport 80 -j DROP
   ```

---

### **7. Save and Make `iptables` Rules Persistent**

Once you have configured your firewall rules, make them persistent across reboots.

1. **On Debian/Ubuntu:**
   Save the rules to a file to persist them across reboots.
   ```bash
   sudo iptables-save > /etc/iptables/rules.v4
   ```

2. **On CentOS/RHEL:**
   ```bash
   sudo service iptables save
   ```

---

### **8. Flush All Rules and Reset Firewall**

If you want to reset the firewall to a clean state, you can flush all existing rules.

1. **Flush all `iptables` rules:**
   ```bash
   sudo iptables -F
   ```

2. **Verify that all rules are removed:**
   ```bash
   sudo iptables -L
   ```

---

### **Conclusion:**

By completing this lab task, you have learned how to:
- Block and allow specific ports.
- Allow traffic from particular IP addresses.
- Configure access based on IP ranges.
- Manage firewall rules for specific protocols like TCP, UDP, and ICMP.

You can continue enhancing this configuration by adding more complex rules, logging dropped packets, and creating custom chains to manage traffic in a more fine-grained manner.
 
Linux Labs
Lab Project - 1
Object: Linux user management lab tasks
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
DURATION: 2 - 3 Hourse
1. Create a New User
Objective:
Learn how to create a new user on a Linux system.
Task:
1.	Use the useradd command to create a new user, e.g., john.
2.	Set a password for the new user using passwd.
3.	Verify the new user by checking the /etc/passwd file.
• Expected Outcome: You will learn how to add users and set passwords for them.
2. Add a User to a Group
Objective:
Learn how to manage user groups in Linux.
Task:
1.	Create a new group (e.g., developers) using groupadd.
2.	Add an existing user (e.g., john) to the group using usermod.
3.	Verify that the user is added to the group by using the groups command.
• Expected Outcome: You will learn to add users to groups and understand group management.
3. Modify User Information
Objective: Learn how to modify user attributes.
Task:
1.	Modify the home directory for user john using usermod.
2.	Change the default shell for john to /bin/bash.
3.	Change the user’s full name using the chfn command.
4.	Verify the changes using grep john /etc/passwd.
• Expected Outcome: You will practice modifying user information.
4. Delete a User
Objective:
Learn how to safely remove users from the system.
Task:
1.	Delete the user john using the userdel command.
2.	Ensure the user's home directory and files are removed by using userdel -r.
3.	Verify the deletion by checking the /etc/passwd file.
• Expected Outcome: You will learn how to remove a user and associated files.
5. Create a System User
Objective: Learn how to create system users.
Task:
1.	Create a system user for an application (e.g., www-data for web server users).
2.	Ensure that the system user has no login shell and that no home directory is created by using useradd -r.
3.	Verify the user is created with no login shell by inspecting /etc/passwd.
• Expected Outcome: You will understand how to create system users that are not meant for interactive logins.
6. Managing User Permissions
Objective: Learn how to manage file permissions for users.
Task:
1.	Create a new user alice.
2.	Create a directory /home/alice_data and set it as rw for the owner, r for the group, and no permissions for others.
3.	Add alice to the group that has access to this directory.
4.	Verify the permissions using ls -l.
• Expected Outcome: You will learn how to manage file and directory permissions based on user groups.
7. Password Aging and Expiry
Objective: Learn how to set password policies for users.
Task:
1.	Set a password expiration period of 90 days for user alice using chage.
2.	Set a warning period to notify the user 7 days before the password expires.
3.	Verify the changes using chage -l alice.
• Expected Outcome: You will learn how to set and manage password expiration and aging policies.
8. Lock and Unlock User Accounts
Objective:
Learn how to lock and unlock user accounts.
Task:
1.	Lock the user account alice by using the passwd -l command.
2.	Verify that the account is locked by trying to log in as alice.
3.	Unlock the account using the passwd -u command.
4.	Verify the account is unlocked by trying to log in again.
• Expected Outcome: You will understand how to temporarily disable and re-enable user accounts.
9. Create and Manage Sudo Access
Objective:
Learn how to provide and manage administrative privileges for users.
Task:
1.	Add a user bob to the sudo group, allowing bob to execute commands as root.
2.	Test by logging in as bob and running a command with sudo.
3.	Optionally, restrict bob’s sudo access by editing the /etc/sudoers file using visudo (e.g., allow only apt-get commands).
• Expected Outcome: You will learn how to grant and restrict sudo access.
10. Set Up User Environment Variables
Objective:
Learn how to set and customize user environment variables.
Task:
1.	Modify the .bashrc file for a user (alice) to set a custom environment variable (e.g., MYVAR=HelloWorld).
2.	Have the user log out and log back in, then check the environment variable using echo $MYVAR.
• Expected Outcome: You will practice setting environment variables that affect user sessions.
11. Create and Manage User Quotas
Objective:
Learn to set disk usage limits for users.
Task:
1.	Enable disk quotas on a specific file system (/home).
2.	Set a soft and hard limit for user alice (e.g., 1 GB for soft, 1.5 GB for hard).
3.	Test the quota by attempting to exceed the disk usage limit.
4.	Verify the user’s quota using the quota command.
• Expected Outcome: You will understand how to limit user disk space usage on a per-user basis.
12. Configure User Shells
Objective:
Learn how to configure a specific shell for users.
Task:
1.	Create a user eve and set their default shell to /bin/zsh using usermod -s /bin/zsh.
2.	Verify that eve’s default shell is set to Zsh by checking /etc/passwd.
3.	Log in as eve and confirm the shell is now Zsh.
• Expected Outcome: You will learn how to change a user’s login shell and verify the change.
13. Automate User Creation with a Script
Objective:
Write a script to automate the creation of users and groups.
Task:
1.	Write a Bash script that takes a username and a group as input.
2.	Create the user, create the group if it does not exist, and add the user to the group.
3.	Set a default password for the new user and notify the administrator by email.
• Expected Outcome: You will automate user and group management tasks, which is useful for system administration.
14. User Account Audit
Objective:
Learn how to audit user accounts.
Task:
1.	Write a script to list all users who have not logged in for the past 90 days.
2.	Optionally, send an email alert for these inactive accounts.
3.	Disable inactive accounts by locking them (passwd -l).
• Expected Outcome: You will practice auditing user activity and manage inactive accounts.
15. Check and Modify User File Permissions
objective:
Learn to manage file permissions and ownership for users.
Task:
1.	Create a file /home/alice/important_file.txt.
2.	Change the ownership of the file to the user alice using chown.
3.	Set the file permissions so that only alice has read and write access, while others have no access.
4.	Verify the permissions using ls -l.
• Expected Outcome: You will gain experience in changing file ownership and setting permissions.
________________________________________
Conclusion
These Linux user management tasks provide hands-on experience with essential administrative tasks, including user creation, group management, permissions, password policies, and user auditing. Completing these tasks will help you develop strong skills in managing users and securing your Linux systems.

 
Linux Labs
Lab Project - 2
Objective: Shell scripting for Automation labs
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
DURATION: 2 - 3 Hourse
Lab 1: Automating System Backup
Objective:
• Learn to create a shell script that automates the process of backing up files and directories.
Tasks:
1.	Create a Backup Script:
 o	Create a script called backup.sh to automate the backup of a directory.
bash
Copy code
nano backup.sh
 o	Add the following content to the script:
bash
Copy code
#!/bin/bash
#Source directory to backup
SRC_DIR="/home/user/data"
#Destination directory where backups will be stored
BACKUP_DIR="/home/user/backups"
#Date format for the backup filename
DATE=$(date +%F)
#Backup filename
BACKUP_FILE="backup_$DATE.tar.gz"
#Create a backup
tar -czf $BACKUP_DIR/$BACKUP_FILE $SRC_DIR
echo "Backup of $SRC_DIR completed successfully and stored in $BACKUP_DIR/$BACKUP_FILE"
2.	Make the Script Executable:
bash
Copy code
chmod +x backup.sh
3.	Run the Backup Script:
 o	Run the script to create a backup:
bash
Copy code
./backup.sh
4.	Schedule the Backup Using Cron:
 o	Open the crontab file to schedule a daily backup.
bash
Copy code
crontab -e
 o	Add the following cron job to run the backup script every day at 2 AM:
bash
Copy code
0 2 * * * /path/to/backup.sh
Outcome:
You will automate the backup of files using a shell script, and schedule it to run daily using cron.
________________________________________
Lab 2: Automating System Updates
Objective:
• Automate system package updates using a shell script to ensure the system is always up to date.
Tasks:
1.	Create the Update Script:
 o	Create a script called auto_update.sh to automate system updates for Debian-based systems (e.g., Ubuntu) or Red Hat-based systems (e.g., CentOS).
bash
Copy code
nano auto_update.sh
 o	Add the following content for Debian/Ubuntu:
bash
Copy code
#!/bin/bash
#Update package list
sudo apt update
#Upgrade installed packages
sudo apt upgrade -y
#Clean up unused packages
sudo apt autoremove -y
echo "System update completed."
o	For Red Hat/CentOS, replace the content with:
bash
Copy code
#!/bin/bash
#Update package list and upgrade packages
sudo yum update -y
#Clean up unused packages
sudo yum autoremove -y
echo "System update completed."
2.	Make the Script Executable:
bash
Copy code
chmod +x auto_update.sh
3.	Run the Update Script:
 o	Run the script to perform an update:
bash
Copy code
./auto_update.sh
4.	Schedule Automatic Updates Using Cron:
 o	Open the crontab file to schedule the update script to run weekly.
bash
Copy code
crontab -e
 o	Add the following cron job to run the script every Sunday at 3 AM:
bash
Copy code
0 3 * * SUN /path/to/auto_update.sh
Outcome:
You will automate the process of keeping your system updated by creating a shell script and scheduling it to run automatically using cron.
________________________________________
Lab 3: Automating Disk Space Monitoring
Objective:
• Automate disk space monitoring and send an alert when disk space usage exceeds a threshold.
Tasks:
1.	Create a Disk Space Monitoring Script:
 o	Create a script called disk_space_monitor.sh to check disk usage and send an email alert if usage exceeds 80%.
bash
Copy code
nano disk_space_monitor.sh
 o	Add the following content:
bash
Copy code
#!/bin/bash
#Set the threshold for disk space usage
THRESHOLD=80
#Get the current disk usage percentage
DISK_USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
#Check if disk usage is above the threshold
if [ $DISK_USAGE -gt $THRESHOLD ]; then
echo "Warning: Disk usage is above $THRESHOLD%.
Current usage: $DISK_USAGE%" | mail -s "Disk Space
Alert" user@example.com
else
echo "Disk usage is below $THRESHOLD%. Current usage: $DISK_USAGE%"
fi
2.	Make the Script Executable:
bash
Copy code
chmod +x disk_space_monitor.sh
3.	Run the Script:

 o	Run the script to check disk usage:
bash
Copy code
./disk_space_monitor.sh
4.	Schedule the Monitoring Script Using Cron:

 o	Open the crontab file to schedule the script to  run every day at 6 AM:
bash
Copy code
crontab -e
 o	Add the following cron job:
bash
Copy code
0 6 * * * /path/to/disk_space_monitor.sh
Outcome:
You will automate disk space monitoring and set up an email alert when disk usage exceeds a predefined threshold.
________________________________________
Lab 4: Automating Log Rotation
Objective:
• Automate the process of rotating logs to avoid disk space issues.
Tasks:
1.	Create a Log Rotation Script:
 o	Create a script called log_rotation.sh to rotate log files in a directory.
bash
Copy code
nano log_rotation.sh
 o	Add the following content:
bash
Copy code
#!/bin/bash
#Directory where logs are stored
LOG_DIR="/var/log/myapp"
#Backup directory for rotated logs
BACKUP_DIR="/var/log/myapp/backup"
#Log file to rotate
LOG_FILE="myapp.log"
#Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR
#Rotate the log file by renaming it with a timestamp
mv $LOG_DIR/$LOG_FILE $BACKUP_DIR/$LOG_FILE-$(date +%F-%T)
#Create a new empty log file
touch $LOG_DIR/$LOG_FILE
#Set permissions on the new log file
chmod 644 $LOG_DIR/$LOG_FILE
echo "Log rotation completed."
2.	Make the Script Executable:
bash
Copy code
chmod +x log_rotation.sh
3.	Run the Script:
 o Run the script to perform log rotation:
bash
Copy code
./log_rotation.sh
4.	Schedule Log Rotation Using Cron:
 o	Open the crontab file to schedule the log rotation to run every day at midnight:
bash
Copy code
crontab -e
 o	Add the following cron job:
bash
Copy code
0 0 * * * /path/to/log_rotation.sh
Outcome:
You will automate log file rotation and archiving to ensure that log files do not consume excessive disk space.
________________________________________
Lab 5: Automating User Account Management
Objective:
• Automate the process of adding and removing users in Linux.
Tasks:
1.	Create a Script to Add Users:
 o	Create a script called add_user.sh to automate adding a user to the system.
bash
Copy code
nano add_user.sh
 o	Add the following content:
bash
Copy code
#!/bin/bash
#Check if username is provided
if [ -z "$1" ]; then
echo "Error: Please provide a username."
exit 1
fi
#Add user to the system
sudo useradd $1
#Set password for the new user
echo "Enter password for user $1:"
sudo passwd $1
echo "User $1 has been added successfully."
2.	Make the Script Executable:
bash
Copy code
chmod +x add_user.sh
3.	Run the Script:
 
 o	Run the script to add a new user:
bash
Copy code
./add_user.sh newuser
4.	Create a Script to Remove Users:
 o	Create a script called remove_user.sh to automate removing a user.
bash
Copy code
nano remove_user.sh
 o	Add the following content:
bash
Copy code
#!/bin/bash
#Check if username is provided
if [ -z "$1" ]; then
echo "Error: Please provide a username."
exit 1
fi
#Remove user from the system
sudo userdel $1
echo "User $1 has been removed successfully."
5.	Run the Script to Remove a User:
bash
Copy code
./remove_user.sh newuser
Outcome:
You will automate user account management, including adding and removing users via shell scripts.
________________________________________
Lab 6: Automating File Cleanup
Objective:
• Automate the deletion of old files in a directory to free up disk space.
Tasks:
1.	Create a Cleanup Script:
 o	Create a script called file_cleanup.sh to remove files older than 30 days.
bash
Copy code
nano file_cleanup.sh
 o	Add the following content:
bash
Copy code
#!/bin/bash
#Directory to clean up
TARGET_DIR="/home/user/temp"
#Find and delete files older than 30 days
find $TARGET_DIR -type f -mtime +30 -exec rm -f {} ;
echo "Old files have been deleted from $TARGET_DIR."
2.	Make the Script Executable:
bash
Copy code
chmod +x file_cleanup.sh
3.	Run the Cleanup Script:
 o	Run the script to clean up old files:
bash
Copy code
./file_cleanup.sh
4.	Schedule the Cleanup Script Using Cron:
 o	Open the crontab file to schedule the cleanup script to run weekly.
bash
Copy code
crontab -e
 o	Add the following cron job:
bash
Copy code
0 3 * * SUN /path/to/file_cleanup.sh
Outcome:
You will automate the cleanup of old files to keep the system free of unnecessary data.
________________________________________
Conclusion:
By completing these Shell Scripting for Automation Labs, you will be able to automate many system administration tasks such as backups, system updates, log rotations, disk space monitoring, and user management. These skills are essential for increasing efficiency and minimizing human error in managing Linux systems
 
Linux Labs
Lab Project - 3
Objective: Linux process management lab
DURATION: 2 - 3 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1 : Process Exploration and Identification
Objective:
Understand how processes work in Linux, and how to identify and explore running processes.
Task:
1.	List Running Processes:

 # Use ps, top, or htop to list all running processes on the system.

 # Understand the difference between ps, top, and htop, and experiment with their options (e.g., ps aux, top -u <username>).

2.	Find a Specific Process:

 # Use pgrep to find the PID (process ID) of a specific running process like apache2 or nginx.
 
 # Use pstree to view a tree of processes and their parent-child relationships.

3.	Investigate Process Details:

 # Use lsof to identify files opened by a process.
 
 # Check the memory usage and CPU time of a process using ps -eo pid,etime,%mem,%cpu,comm.
Outcome:
This lab will help you become familiar with the tools and techniques used to explore and gather information about running processes in Linux.
________________________________________
Lab 2 : Process Control and Termination
Objective:
Learn how to control, pause, resume, and terminate processes in Linux.
Task:
1.	Send Signals to Processes:

 # Use kill to send signals to processes. Try sending a SIGTERM and SIGKILL to terminate a process by PID.

 # Use kill -s STOP <PID> and kill -s CONT <PID> to stop and resume a process.

2.	Send Custom Signals:

 # Send a SIGINT signal to a running process (e.g., when running a program in the terminal, use Ctrl+C or kill -s SIGINT <PID>).

3.	Test Process Termination:
 
 # Start a process, for example, sleep 300, then find its PID and try to terminate it using kill or kill -9.
Outcome:
You will gain experience in controlling the execution of processes and understand how to manage them using different signals.
________________________________________
Lab 3 : Managing Background and Foreground Processes
Objective:
Learn how to run processes in the background and manage jobs effectively.
Task:
1.	Run a Process in the Background:
 
 # Start a process in the background using &, e.g., sleep 100 &.
 
 # Use jobs to see a list of background jobs.

2.	Bring a Process to the Foreground:
 
 # Use the fg command to bring a background process to the foreground.

3.	Pause and Resume a Process:
 
 # Pause a background process using Ctrl+Z and resume it in the background with the bg command.

4.	Control Multiple Jobs:
 
 # Start multiple jobs in the background and manage them with jobs, fg, and bg.
Outcome:
This lab will help you practice managing processes in the background and foreground, useful for multitasking on the command line.
________________________________________
Lab 4 : Monitoring System Performance and Resource Usage
Objective:
Learn how to monitor system resources and analyze processes consuming system resources.
Task:
1.	Monitor CPU Usage:
 
 # Use top or htop to monitor CPU usage in real-time.
 
 # Look for processes consuming high CPU and analyze them.

2.	Monitor Memory Usage:
 
 # Use free or vmstat to check system memory usage.
 
 # Use ps aux --sort=-%mem to find processes using the most memory.

3.	Disk Usage and I/O Monitoring:

 # Use iotop or dstat to monitor real-time disk I/O usage by processes.

4. Check Process Limits:
 
 # Use ulimit to check and modify user limits on processes (e.g., maximum number of open files).
Outcome:
You will learn to use various monitoring tools to keep track of system performance, identify resource hogs, and improve system efficiency.
________________________________________
Lab 5 : Managing Daemons and Background Services
Objective:
Learn how to manage background services and daemons in Linux.
Task:
1.	Start and Stop Services:
 
 # Use systemctl to start, stop, and restart system services (e.g., systemctl start apache2, systemctl stop nginx).

2.	Enable/Disable Services on Boot:

 # Use systemctl enable and systemctl disable to manage whether a service starts on boot.

3.	Check Service Status:
 
 # Use systemctl status to check the status of a service (e.g., systemctl status apache2).

4.	Managing Logs for Services:

 # Use journalctl to check logs for systemd services.
 
 # Filter logs for specific services or time periods to troubleshoot issues.
Outcome:
This lab will give you hands-on experience with managing system services and daemons, which is crucial for server administration.
________________________________________
Lab 6 : Process Scheduling and Prioritization
Objective:
Learn how to control process priority and manage process scheduling.
Task:
1.	Change Process Priority (Nice Value):

 # Use nice to start a new process with a custom priority level (e.g., nice -n 10 command).
 
 # Use renice to change the priority of an already running process by its PID (e.g., renice -n -5 <PID>).

2.	Scheduling Processes:
 
 # Use at to schedule a one-time task (e.g., at 09:00 to run a script).
 
 # Use cron to schedule recurring tasks by adding entries to /etc/crontab or using crontab -e for user-specific jobs.

3.	Monitor Process Execution Time:
 
 # Use time to measure the execution time of a command or script.
Outcome:
You will learn how to manage process priority and scheduling, useful for optimizing resource allocation and automation of tasks.
________________________________________
Lab 7 : Investigating and Debugging Stuck Processes
Objective:
Learn how to identify and debug processes that are stuck or unresponsive.
Task:
1.	Check for Stuck Processes:

 # Use ps or top to identify processes that are stuck in a specific state, like D (uninterruptible sleep).

2.	Trace Process Execution:
 
 # Use strace to trace the system calls made by a process (e.g., strace -p <PID>).

3.	Analyze Process Core Dumps:

 # Set up core dumps for processes by configuring /etc/security/limits.conf.
 
 # Use gdb to analyze the core dump of a crashed process.

4.	Terminate or Kill a Stuck Process:

 # Use kill -9 to forcefully terminate a stuck process.

 # Investigate logs (e.g., /var/log/syslog) for additional clues.
Outcome:
This lab will help you practice troubleshooting and debugging stuck or unresponsive processes, a critical skill in system administration.
________________________________________
Lab 8 : Containerized Processes with Docker
Objective:
Manage processes within Docker containers and understand container lifecycle.
Task:
1.	Start a Docker Container:
 
 # Use docker run to start a container from an image (e.g., docker run -d nginx).

2.	Monitor Processes Inside Containers:
 
 # Use docker exec to run commands like top or ps inside a running container to view its processes.

3.	Stop and Restart Containers:
 
 # Use docker stop and docker restart to manage containerized processes.

4.	Debugging a Stuck Container:

 # Use docker logs to view logs and diagnose issues in a container.

 # Check container resource usage using docker stats.
Outcome:
You will gain practical experience managing processes inside Docker containers, an essential skill for modern application deployment.
________________________________________
Lab 9 : Process Resource Usage and Optimization
Objective:
Optimize processes to improve system performance and reduce resource usage.
Task:
1. Analyze Resource Usage:
 
 # Use ps aux --sort=-%mem or top to find the processes consuming the most memory and CPU.

2. Optimize Memory Usage:
 
 # Identify memory leaks or inefficient memory usage with valgrind or smem.

3. Optimize CPU Usage:

 # Use cpulimit or nice to adjust CPU resource allocation for specific processes.

4. Tune System Parameters:
 
 # Tune kernel parameters related to process management using sysctl (e.g., sysctl -w vm.swappiness=10).
Outcome:
You will learn to optimize resource usage by fine-tuning processes and system parameters for improved performance.
________________________________________
Conclusion:
These Linux process management labs will provide you with practical, hands-on experience in managing processes, monitoring system resources, debugging issues, and optimizing performance. Each lab mimics real-life tasks and will help you develop critical skills for system administration and troubleshooting.

Linux Labs
Lab Project - 4
Objective: Neetworking with Linux
DURATION: 2 - 3 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1: Basic Network Configuration and Testing
Objective:
• Understand how to configure and test basic network settings on a Linux system.
Tasks:
1.	Check Network Interfaces:
 
 o	Use ip or ifconfig to list all available network interfaces on the system.
bash
Copy code
ip a
#or
ifconfig
2.	Configure IP Address Manually:
 
 o	Use the ip command to assign a static IP address to an interface.
bash
Copy code
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip link set eth0 up
3.	Verify the Configuration:
 
 o	Verify the IP address configuration using ip or ifconfig.
bash
Copy code
ip a
4.	Test the Network Connectivity:
 
 o Use ping to test the network connectivity between the local machine and a remote host.
bash
Copy code
ping -c 4 8.8.8.8
5.	Configure Default Gateway:
 
 o Use ip to add a default gateway for routing.
bash
Copy code
sudo ip route add default via 192.168.1.1
6.	Verify Routing Table:
 
 o Check the routing table to ensure that the default gateway is correctly configured.
bash
Copy code
ip route
7.	DNS Configuration:
 
 o Edit /etc/resolv.conf to configure DNS servers:
bash
Copy code
sudo nano /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
8.	Test Name Resolution:

 o Test the DNS configuration by pinging a domain.
bash
Copy code
ping -c 4 google.com
Outcome:
You will have configured the network interface with a static IP address, default gateway, and DNS, and tested connectivity using ping.
________________________________________
Lab 2: Dynamic IP Address Configuration using DHCP
Objective:
• Learn how to configure and test dynamic IP address assignment using DHCP.
Tasks:
1.	Configure DHCP Client:

 o	Ensure that the system is set to obtain an IP address automatically from a DHCP server. Modify the network interface configuration file, usually located at /etc/network/interfaces (Debian/Ubuntu) or /etc/sysconfig/network-scripts/ifcfg-eth0 (CentOS/RHEL):
#Debian/Ubuntu:
bash
Copy code
sudo nano /etc/network/interfaces
auto eth0
iface eth0 inet dhcp
#CentOS/RHEL:
bash
Copy code
sudo nano /etc/sysconfig/network-scripts/ifcfg-eth0
BOOTPROTO=dhcp
ONBOOT=yes
2.	Restart Networking Service:

 o Restart the networking service to apply changes:
#Debian/Ubuntu:
bash
Copy code
sudo systemctl restart networking
#CentOS/RHEL:
bash
Copy code
sudo systemctl restart network
3.	Verify DHCP Assignment:

 o Use ip a or ifconfig to check if the IP address has been assigned by the DHCP server.

4.	Verify Network Connectivity:
 
 o	Use ping to test network connectivity and confirm that the DHCP-assigned IP works:
bash
Copy code
ping -c 4 google.com
Outcome:
You will configure a system to obtain an IP address dynamically via DHCP and verify the network connectivity.
________________________________________
Lab 3: Network Troubleshooting Tools
Objective:
• Use networking tools to troubleshoot common network issues in Linux.
Tasks:
1.  Ping Test:
 
 o Use the ping command to check the network connectivity to another system.
bash
Copy code
ping -c 4 192.168.1.1
2.	Traceroute:
 
 o Use traceroute to track the route that packets take to reach a destination.
bash
Copy code
sudo apt install traceroute # Ubuntu/Debian
sudo yum install traceroute # CentOS/RHEL
traceroute google.com
3.	Check DNS Resolution:
 
 o	Use dig or nslookup to check DNS resolution for a domain.
bash
Copy code
dig google.com
#or
nslookup google.com
4.	Network Interface Status:
 
 o Use ethtool to check the status of the network interface (whether it's up, down, speed, etc.).
bash
Copy code
sudo apt install ethtool # Ubuntu/Debian
sudo yum install ethtool # CentOS/RHEL
sudo ethtool eth0
5.	View Routing Table:
 
 o Use ip route or netstat -r to view the current routing table.
bash
Copy code
ip route
#or
netstat -r
6.	Check Active Connections:
 
 o Use netstat or ss to view active network connections on the system.
bash
Copy code
netstat -tuln
#or
ss -tuln
7.	Check Network Configuration with ifconfig or ip:
 
 o Verify network interface configuration using ifconfig or ip.
bash
Copy code
ifconfig
#or
ip a
Outcome:
You will have gained experience using various Linux network troubleshooting tools to diagnose and resolve network issues.
________________________________________
Lab 4: Configuring Advanced Network Settings (Static Routes, VLANs, etc.)
Objective:
• Learn how to configure advanced network settings such as static routes and VLANs on a Linux system.
Tasks:
1.	Add a Static Route:

 o Use ip to add a static route. For example, to route traffic destined for 192.168.2.0/24 via a gateway 192.168.1.1:
bash
Copy code
sudo ip route add 192.168.2.0/24 via 192.168.1.1
2.	View Routing Table:

 o View the routing table to ensure the static route has been added:
bash
Copy code
ip route
3.	Configure a VLAN Interface:
 
 o Create a VLAN interface using vconfig or ip commands. For example, to create VLAN 10 on interface eth0:
bash
Copy code
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip addr add 192.168.10.1/24 dev eth0.10
sudo ip link set eth0.10 up
4.	Verify VLAN Configuration:
 
 o Verify the VLAN interface is up and has the correct IP address:
bash
Copy code
ip a show eth0.10
5.	Enable IP Forwarding (for Routing Between Networks):

 o	Enable IP forwarding to allow routing between different subnets:
bash
Copy code
sudo sysctl -w net.ipv4.ip_forward=1
6.	Configure NAT for Internet Sharing:
 
 o Configure Network Address Translation (NAT) using iptables to share the internet connection with a local network:
bash
Copy code
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1
Outcome:
You will have learned how to configure static routes, VLANs, and network address translation (NAT) on Linux.
________________________________________
Lab 5: Securing Linux Network Services
Objective:
• Learn how to secure network services on a Linux system by configuring firewalls and using SSH for secure communication.
Tasks:
1.	Configure UFW (Uncomplicated Firewall) on Ubuntu/Debian:

 o Install and configure UFW to allow only certain services (e.g., SSH, HTTP):
bash
Copy code
sudo apt install ufw
sudo ufw allow ssh
sudo ufw allow http
sudo ufw enable
sudo ufw status 2. Configure FirewallD on CentOS/RHEL:
 o Install and configure firewalld to allow only certain services:
bash
Copy code
sudo systemctl start firewalld
sudo firewall-cmd --permanent --zone=public --add-service=ssh
sudo firewall-cmd --permanent --zone=public --add-service=http
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
3.	Secure SSH Access:

 o Disable root login and change the SSH port by editing /etc/ssh/sshd_config:
bash
Copy code
PermitRootLogin no
Port 2222
 o	Restart the SSH service:
bash
Copy code
sudo systemctl restart sshd
4.	Verify Firewall Configuration:

 o Use ufw status or firewall-cmd --list-all to verify that only the required services are accessible.
Outcome:
You will have configured firewalls to secure network services and restricted SSH access for enhanced security.
________________________________________
Conclusion:
These Linux Networking Labs provide you with the foundational knowledge needed to configure and troubleshoot networking on a Linux system. You will learn how to set up basic and advanced networking configurations, diagnose connectivity issues, and secure Linux network services through firewalls and SSH. By completing these labs, you'll gain hands-on experience that will help you manage and secure Linux-based networks.
Linux Labs
Lab Project - 5
Objective: Linux Sudo Access
DURATION: 2 - 3 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1: Introduction to sudo
Objective:
• Understand how sudo works and gain basic experience using it.
Tasks:
1.	Check for sudo Installation:
 
 o  Verify that sudo is installed on your system.
bash
Copy code
which sudo
 o	If it is not installed, you can install it using the following command:
#On Ubuntu/Debian:
bash
Copy code
sudo apt install sudo
#On CentOS/RHEL:
bash
Copy code
sudo yum install sudo
2.	Verify sudo Access for Current User:
 
 o	Check whether the current user has sudo privileges by running a command that requires superuser permissions, such as:
bash
Copy code
sudo whoami
 o	This should return root if the user has sudo access.

3.	Execute Commands with sudo:

 o	Run a simple system command with sudo to confirm access. For example, try updating the system package list:
bash
Copy code
sudo apt update # Ubuntu/Debian
sudo yum update # CentOS/RHEL
4.	Exit the sudo Session:

 o	After running the command, exit the root session by simply typing exit or waiting for the session timeout.
Outcome:
You will have learned how to check if sudo is installed, verify sudo access, and run commands with sudo.
________________________________________
Lab 2: Configuring Sudo Access
Objective:
• Learn how to configure sudo access for specific users by editing the sudoers file.
Tasks:
1.	Open the Sudoers File Safely:
 
 o	Use visudo to edit the sudoers file, which is the correct and safest way to modify sudo permissions.
bash
Copy code
sudo visudo
2.	Grant Sudo Access to a User:

 o	Add a new user to the sudoers file by adding the following line under the user section:
bash
Copy code
username ALL=(ALL) ALL
 o	Replace username with the actual username you want to grant sudo access to.

3.	Grant Sudo Access to a Group:
 
 o	To grant sudo access to all members of a specific group (e.g., admin or sudo), you can add:
bash
Copy code
%groupname ALL=(ALL) ALL
 o	Replace groupname with the group you want to grant sudo access to.

4.	Apply the Changes:

 o	Save and exit the visudo editor (Ctrl+X, then Y to confirm, and Enter to save).
 
 o	The changes will take effect immediately.

5.	Test the New User’s Sudo Access:
 
 o	Log in as the newly added user or use su to switch to that user:
bash
Copy code
su - username
 o	Test sudo access by running:
bash
Copy code
sudo whoami
Outcome:
You will be able to grant and manage sudo access for specific users and groups.
________________________________________
Lab 3: Understanding and Configuring Sudo Permissions
Objective:
• Understand how to control specific sudo permissions (what commands a user can run with sudo).
Tasks:
1.	Limit Sudo Access to Specific Commands:

 o	Open the sudoers file and add a rule that only allows a user to run specific commands. For example:
bash
Copy code
username ALL=(ALL) /usr/bin/apt, /usr/bin/dpkg
 o	This allows the user to run only apt and dpkg with sudo.

2.	Set NOPASSWD for Certain Commands:
 
 o	You can configure sudo to not ask for a password for specific commands. Add the following line in the sudoers file:
bash
Copy code
username ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/dpkg
 o	This allows the user to run apt and dpkg without entering a password.

3.	Restrict Access to Only Certain Users:

 o	You can also configure sudo to only allow certain users to execute certain commands. For example:
bash
Copy code
username ALL=(ALL) /usr/bin/apt
%admin ALL=(ALL) /usr/bin/apt
 o	This allows username and all users in the admin group to run apt.

4.	Apply the Changes and Test:
 
 o	Save the sudoers file and exit.
 
 o	Test the restricted access by running only the permitted commands as the user.
Outcome:
You will learn how to restrict and customize sudo permissions to enhance security.
________________________________________
Lab 4: Sudo Logs and Auditing
Objective:
• Learn how to view and manage sudo logs to track user activity.
Tasks:
1.	Check Sudo Logs:
 
 o	By default, sudo logs all commands run to /var/log/auth.log (on Ubuntu/Debian) or /var/log/secure (on CentOS/RHEL).

 o	View the sudo logs by running:
bash
Copy code
sudo cat /var/log/auth.log # Ubuntu/Debian
sudo cat /var/log/secure # CentOS/RHEL
2.	Search for Sudo Commands:

 o	Use grep to search for sudo-related logs:
bash
Copy code
sudo grep 'sudo' /var/log/auth.log
3.	Configure Logging Level:

 o	You can configure the logging level of sudo by modifying the sudoers file.

 o	Add a line to the sudoers file to set the logging level (optional):
bash
Copy code
Defaults logfile="/var/log/sudo.log"
4.	View the Sudo Log File:

 o	You can now monitor the sudo log file to track all sudo commands used by different users:
bash
Copy code
sudo tail -f /var/log/sudo.log
Outcome:
You will have learned how to track and audit sudo usage, which is crucial for security and accountability.
________________________________________
Lab 5: Sudo Timeout and Tuning
Objective:
• Learn how to configure the sudo session timeout to improve security.
Tasks:
1.	Set the sudo Timeout:
 
 o	The sudo session timeout can be controlled by setting the timestamp_timeout parameter in the sudoers file.

 o	To configure the timeout (in minutes), edit the sudoers file:
bash
Copy code
Defaults timestamp_timeout=10
 o	This means sudo will prompt for a password every 10 minutes.

2.	Disable the Timeout:

 o	To disable the timeout entirely, set the timeout to 0:
bash
Copy code
Defaults timestamp_timeout=0
3.	Test the Timeout Configuration:

 o	Run a sudo command and wait for the specified timeout duration. After the timeout, sudo should prompt you for the password again.

4.	Set a Negative Timeout:
 
 o	If you set timestamp_timeout to -1, sudo will ask for the password every time a sudo command is executed:
bash
Copy code
Defaults timestamp_timeout=-1
Outcome:
You will learn how to adjust the timeout settings for sudo, which is important for managing the security of long-running sessions.
________________________________________
Lab 6: Troubleshooting Sudo Issues
Objective:
• Learn how to troubleshoot common sudo access issues.
Tasks:
1.	Check User's Group Membership:
 
 o	Verify that the user is part of the correct group (sudo or wheel) by running:
bash
Copy code
groups username
2.	Verify Permissions in the Sudoers File:

 o	Check for syntax errors in the sudoers file by running:
bash
Copy code
sudo visudo
 o	Ensure that there are no conflicting rules or misconfigurations.

3.	Check Sudo Log for Errors:
 
 o	If a user cannot execute sudo, check the logs for any errors related to authentication.

4.	Test with Another User:

 o	If one user cannot use sudo, try using another user with sudo access to determine if the problem is user-specific.
Outcome:
You will gain skills in diagnosing and fixing common sudo configuration problems.
________________________________________
Conclusion:
These Sudo Access Labs will equip you with a deep understanding of how to configure, manage, and troubleshoot sudo access on a Linux system. You’ll be able to securely provide limited administrative access, audit user activity, and ensure proper use of system resources. These skills are fundamental for any system administrator responsible for maintaining Linux environments.
 
Linux Labs
Lab Project - 6
Objective: Linux SSH Connectivity Labs
DURATION: 2 - 3 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1: Basic SSH Connectivity
Objective:
• Learn how to set up and use SSH for basic remote access.
Tasks:
 1.	Install OpenSSH Server:
  
  o	Install the OpenSSH server package on a Linux machine (if not already installed).
  
  o	For Ubuntu/Debian-based systems:
bash
Copy code
sudo apt update
sudo apt install openssh-server
  o	For CentOS/RHEL-based systems:
bash
Copy code
sudo yum install openssh-server
 2.	Start and Enable SSH Service:

  o	Start the SSH service and enable it to start at boot.
bash
Copy code
sudo systemctl start ssh
sudo systemctl enable ssh
 3.	Check SSH Service Status:

  o	Verify that the SSH server is running.
bash
Copy code
sudo systemctl status ssh
 4.	Verify SSH Port:
  
  o	Ensure SSH is running on port 22 (default port).
bash
Copy code
sudo netstat -tuln | grep :22
 5.	Connect to the Remote Server via SSH:

  o	From another machine, connect to the SSH server using:
bash
Copy code
ssh username@server_ip
  o	Replace username with a valid user on the remote server and server_ip with the IP address of the server.

 6.	Log Out of SSH Session:

  o	Use the exit command to end the SSH session.
Outcome:
You will have established a basic SSH connection and learned how to install and start the SSH server on a Linux machine.
________________________________________
Lab 2: SSH Key-Based Authentication
Objective:
• Learn how to configure SSH key-based authentication for more secure and password-less login.
Tasks:
 1.	Generate SSH Key Pair:

  o	On your local machine, generate a new SSH key pair using ssh-keygen.
bash
Copy code
ssh-keygen -t rsa -b 4096
  o	Follow the prompts to save the key to a default location (~/.ssh/id_rsa) and optionally set a passphrase.

 2.	Copy Public Key to the Remote Server:

  o	Use ssh-copy-id to copy the public key to the remote server.
bash
Copy code
ssh-copy-id username@server_ip
 3.	Test Key-Based Authentication:
  
  o	Attempt to SSH into the remote server. You should be logged in without needing to enter the password.
bash
Copy code
ssh username@server_ip
 4.	Disable Password Authentication (optional):

  o	For additional security, you can disable password-based login on the server by modifying the SSH configuration file (/etc/ssh/sshd_config).
#Set PasswordAuthentication to no.
bash
Copy code
sudo nano /etc/ssh/sshd_config
PasswordAuthentication no
  o	Restart the SSH service:
bash
Copy code
sudo systemctl restart ssh
 5.	Test SSH Connection After Disabling Password Authentication:

  o	Try to SSH into the server again. You should only be able to connect using the SSH key.
Outcome:
You will have configured SSH key-based authentication, improving security by avoiding password-based login.
________________________________________
Lab 3: SSH Configuration and Security
Objective:
• Learn how to harden and secure your SSH configuration.
Tasks:
 1.	Change Default SSH Port:
  
  o	Edit the SSH configuration file (/etc/ssh/sshd_config) to change the default port from 22 to another port (e.g., 2222).
bash
Copy code
sudo nano /etc/ssh/sshd_config
Port 2222
  o	Restart the SSH service:
bash
Copy code
sudo systemctl restart ssh
  o	Test the connection by specifying the new port:
bash
Copy code
ssh username@server_ip -p 2222
 2.	Disable Root Login via SSH:

  o	Modify /etc/ssh/sshd_config to disable direct root login.
bash
Copy code
sudo nano /etc/ssh/sshd_config
PermitRootLogin no
  o	Restart the SSH service:
bash
Copy code
sudo systemctl restart ssh
 3.	Limit SSH Access to Specific Users or Groups:

  o	Use the AllowUsers or AllowGroups directive in /etc/ssh/sshd_config to allow only specific users or groups to log in via SSH.
bash
Copy code
sudo nano /etc/ssh/sshd_config
AllowUsers user1 user2
#or
AllowGroups sshusers
  o	Restart the SSH service:
bash
Copy code
sudo systemctl restart ssh
 4.	Enable SSH Rate Limiting with Fail2Ban:

  o	Install fail2ban to block IP addresses that attempt too many failed SSH login attempts.
bash
Copy code
sudo apt install fail2ban
  o	Enable and start the service:
bash
Copy code
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
 5.	Test Security Configurations:

  o	Test that root login is disabled, specific users/groups can log in, and the new SSH port is working correctly.

  o	Attempt SSH connections with invalid passwords to check if fail2ban blocks the IP after multiple failed attempts.
Outcome:
You will have configured a secure SSH environment by changing default settings, restricting access, and adding fail2ban protection.
________________________________________
Lab 4: SSH Tunneling and Port Forwarding
Objective:
• Learn how to set up SSH tunneling for secure communication between two systems.
Tasks:
 1.	Local Port Forwarding:
  
  o	Forward a local port to a remote server. For example, if you have a web server running on port 80 on a remote system, you can forward it to a local port:
bash
Copy code
ssh -L 8080:localhost:80 username@server_ip
  o	After establishing the connection, you can access the remote web server by navigating to http://localhost:8080 on your local browser.
 
 2.	Remote Port Forwarding:
  
  o	Forward a remote port to a local system. For example, if you want to access a service running locally on port 3306 from a remote server, you can use:
bash
Copy code
ssh -R 3306:localhost:3306 username@server_ip
 3.	Dynamic Port Forwarding (SOCKS Proxy):

  o	Set up SSH to create a SOCKS proxy for secure browsing.
bash
Copy code
ssh -D 1080 username@server_ip
  o	Configure your browser to use the SOCKS proxy on port 1080 to securely browse the web.

 4.	Test the Port Forwarding:

  o	For local and remote port forwarding, test the service by connecting to the local forwarded port (e.g., a web server or database).

  o	For SOCKS proxy, verify browsing through the secure tunnel.
Outcome:
You will understand and be able to implement SSH tunneling to securely forward ports and set up a SOCKS proxy.
________________________________________
Lab 5: SSH Agent and Forwarding
Objective:
• Learn to use SSH agent forwarding for accessing remote servers that require authentication via SSH keys.
Tasks:
 1.	Start the SSH Agent:

  o	Start the SSH agent on your local machine.
bash
Copy code
eval $(ssh-agent -s)
 2.	Add SSH Key to the Agent:
  
  o	Add your private key to the SSH agent.
bash
Copy code
ssh-add ~/.ssh/id_rsa
 3.	Enable SSH Agent Forwarding:

  o	On your local machine, configure ~/.ssh/config to enable agent forwarding.
bash
Copy code
Host *
ForwardAgent yes
 4.	Access Remote Server with SSH Agent Forwarding:
  
  o	SSH into the first server and then SSH from that server to a second server. The SSH agent on your local machine will be forwarded, allowing you to use the SSH key for the second connection without needing to copy it over.
  
  o	Example:
bash
Copy code
ssh username@first_server_ip
ssh username@second_server_ip
 5.	Verify SSH Agent Forwarding:

  o	Check if agent forwarding is enabled by running the following on the second server:
bash
Copy code
ssh-add -l
Outcome:
You will understand how to use SSH agent forwarding to securely access multiple systems without copying SSH keys.
________________________________________
Conclusion:
These SSH connectivity labs cover everything from basic setup to advanced configurations such as key-based authentication, security hardening, SSH tunneling, and agent forwarding. By completing these labs, you'll gain hands-on experience with SSH, which is essential for remote administration, system security, and networking tasks.
 
Linux Labs
Lab Project - 7
Objective: Linux filesystem management lab
DURATION: 2 - 3 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1: Disk Partitioning and File System Creation
Objective: Learn how to partition a disk, create filesystems, and mount them.
Task:
 1.	Partition a Disk:
  
  #  Use fdisk or parted to create partitions on a disk (e.g., /dev/sdb).
  
  #  Create a primary partition and a swap partition.
  
  #  Use lsblk and fdisk -l to confirm the new partitions.
 
 2.	Create File Systems:
  
  #  Format the partitions with different file systems (e.g., ext4, xfs, btrfs) using the mkfs command.
  
  #  Check the file system using fsck.
 
 3.	Mount Partitions:
  
  #  Mount the new partitions manually using mount (e.g., mount /dev/sdb1 to /mnt/data).

  #  Add entries to /etc/fstab to ensure automatic mounting on boot.
 
 4.	Verify and Access:
  
  #  Use df -h to check mounted file systems and disk usage.
  
  #  Access files from the new mount point and test read/write operations.
Outcome:
This lab will help you gain hands-on experience in disk partitioning, file system creation, and mounting partitions on Linux.
________________________________________
Lab 2: Directory Structure and Permissions Management
Objective: Practice managing directories and controlling permissions in a Linux file system.
Task:
 1.	Create Directories:
  
  #	Use the mkdir command to create a complex directory structure (e.g., /home/user/docs, /home/user/projects).

 2.	Set Permissions:
  
  #	Use chmod to set permissions for different directories and files. For example, set read/write/execute permissions for the owner, group, and others.
  
  #	Use chown to change ownership of files and directories.

 3.	Test Directory Permissions:

  #	Ensure that users without proper permissions cannot access directories.

  #	Test creating, deleting, and modifying files inside these directories.

 4.	Use Access Control Lists (ACLs):

  #	Use setfacl to set additional ACLs for files and directories, allowing more fine-grained control over file access.
Outcome:
This lab will help you manage directories, control access to them, and work with advanced permissions and ACLs.
________________________________________
Lab 3: Mounting and Using Network File Systems (NFS)
Objective: Set up and mount a Network File System (NFS) to share files between two Linux machines.
Task:
 1.	Install NFS Server:
  
  #	Install and configure the NFS server on a Linux machine using apt-get or yum.

  #	Edit /etc/exports to specify which directories are shared (e.g., /mnt/data).
 
 2.	Configure NFS Server:
  
  #  	Export the shared directory using the exportfs command.
  
  #	Start the NFS service with systemctl start nfs-server.

 3.	Mount NFS on Client:

  # 	On another Linux machine, mount the shared directory using the mount command (e.g., mount <server_ip>:/mnt/data /mnt/nfs).

 4.	Verify NFS Functionality:
 
  #	Test file creation and modification across the network to verify that NFS is functioning correctly.
Outcome:
This lab will teach you how to configure and use NFS for sharing files across multiple systems, a critical task for centralized storage in Linux environments.
________________________________________
Lab 4: Disk Usage Analysis and Cleanup
Objective: Learn to analyze disk usage and clean up disk space by removing unnecessary files.
Task:
 1.	Check Disk Usage:
  
  #	Use the df -h command to check the disk space usage of the file system.

  #	Use du -sh <directory> to check the size of specific directories.

 2.	Find Large Files:

  #	Use find / -type f -size +100M to locate files larger than 100MB.

  #	Use ncdu to interactively view and navigate through disk usage.

 3.	Clean Up Old Files:

  #	Identify and delete unnecessary files using the rm command.

  #	Empty the trash using rm -rf ~/.local/share/Trash/*.

 4.	Automate Cleanup:
  
  #	Set up a cron job to automate cleanup tasks like deleting old log files or temporary files.
Outcome:
This lab will help you manage disk usage effectively by identifying and cleaning up large or unnecessary files.
________________________________________
Lab 5: LVM (Logical Volume Management) Setup
Objective: Set up and manage logical volumes for flexible disk space management.
Task:
 1.	Create Physical Volume (PV):

   #	Use pvcreate to initialize a physical volume on a disk (e.g., /dev/sdb).

 2.	Create Volume Group (VG):
  
  #	Use vgcreate to create a volume group (e.g., vg_data).

 3.	Create Logical Volume (LV):
  
  #	Use lvcreate to create a logical volume from the volume group (e.g., lv_data).

 4.	Create File System:

  #	Format the logical volume with a file system (e.g., mkfs.ext4 /dev/vg_data/lv_data).

 5.	Mount and Extend Logical Volume:
 
  #   Mount the logical volume and use lvextend to increase its size as needed.

 6.	Resize File System:
  
  #	Use resize2fs or xfs_growfs to resize the file system after extending the logical volume.
Outcome:
You will learn how to create, manage, and resize logical volumes using LVM, which is a flexible method for managing disk space in Linux.
________________________________________
Lab 6: Disk Encryption with LUKS
Objective: Set up disk encryption using LUKS to secure sensitive data.
Task:
 1.	Install Cryptsetup:
  
  #	Install cryptsetup to manage LUKS encryption.
 
 2.	Create an Encrypted Partition:
  
  #  	Use cryptsetup luksFormat /dev/sdb1 to encrypt the partition.
 
 3.	Open Encrypted Volume:
  
  #	Use cryptsetup luksOpen /dev/sdb1 encrypted_data to open the encrypted volume.
 
 4.	Create File System on Encrypted Partition:
  
  #	Format the opened volume with mkfs.ext4 or another file system.
 
 5.	Mount and Configure Auto-Mount:

  #	Mount the encrypted partition and configure /etc/crypttab for automatic unlocking during boot.

 6.	Verify Encryption:
  
  #	Test encryption by mounting the partition and ensuring data is unreadable without the correct passphrase.
Outcome:
This lab will help you secure sensitive data by setting up disk encryption with LUKS, which is crucial for protecting data in transit or on disk.
________________________________________
Lab 7: Creating and Managing Swap Space
Objective: Set up and manage swap space to improve system performance, especially when physical memory is full.
Task:
 1.	Create a Swap Partition:

  #	Use fdisk or parted to create a swap partition.

  #	Format the partition with mkswap.
 
 2.	Enable Swap:
  
  #	Enable the swap space using swapon /dev/sdb1.
 
 3.	Add Swap to /etc/fstab:
  
  #	Edit /etc/fstab to ensure that the swap partition is mounted automatically at boot.
 
 4.	Create Swap File:
  
  #	Create a swap file using dd if=/dev/zero of=/swapfile bs=1M count=1024 and enable it using swapon /swapfile.
 
 5.	Verify Swap:

  #	Use swapon -s to verify the active swap spaces.

  #	Check system memory and swap usage using free -h.
Outcome:
You will gain knowledge of how to manage swap space to optimize system performance.
________________________________________
Lab 8: Filesystem Repair with fsck
Objective: Learn how to check and repair a corrupted file system.
Task:
 1.	Simulate File System Corruption:
  
  #	Unmount a file system and use mount -o ro to create read-only access for a file system, simulating corruption.

 2.	Run fsck:
  
  #	Use fsck /dev/sdb1 to check and repair the file system.
 
 3.	Repair Options:
  
  #	Explore different fsck options such as -A (check all file systems) or -y (automatically fix errors).
 
 4.	Recover Lost Files:
 
  #	Use extundelete to attempt recovery of deleted files from an ext3/ext4 file system.
Outcome:
You will learn how to use fsck for diagnosing and fixing file system errors.
________________________________________
Lab 9: File System Quotas
Objective: Set up and manage file system quotas to control disk space usage for users and groups.
Task:
 1.	Enable Quotas on File System:

  #	Edit /etc/fstab to enable quotas on a partition (e.g., usrquota, grpquota).

  #	Remount the file system using mount -o remount /.
 
 2.	Create and Assign Quotas:
  
  #	Use edquota to set soft and hard disk quotas for users.
 
 3.	Monitor Quotas:

  #	Use repquota to generate reports on disk usage by users and groups.
 
 4.	Test Quotas:
  
  #	Test the quotas by trying to create files that exceed the assigned limits.
Outcome:
You will learn to implement and manage disk quotas to control storage usage in a multi-user environment.
________________________________________
Conclusion
These Linux filesystem management labs cover a wide range of essential tasks, including partitioning, mounting, disk usage analysis, file system creation, management, and troubleshooting. These labs are designed to give you practical experience with the Linux file system, which is critical for system administration and maintaining a secure and efficient storage infrastructure.
 
Linux Labs
Lab Project - 8
Objective: Linux environment management lab
DURATION: 3 - 4.5 Hourse
PRE-REQUISITES:
Oracle VirtualBox or VMWare, Ubuntu installed.
Lab 1: Configuring and Managing User Environments
Objective: Learn to manage and configure user-specific environment settings in Linux.
Task:
 1.	Set Environment Variables:
  
  #	Set environment variables like PATH, EDITOR, and JAVA_HOME in /etc/profile, /etc/bash.bashrc, and user-specific files like ~/.bashrc.
  
  #	Verify the environment variables using echo $VARIABLE_NAME.
 
 2.	Configure Bash Prompt:

  #	Modify the PS1 variable to customize the command prompt.
  
  #	Set a colored prompt and add user-specific information like username, hostname, and current directory.

 3.	Create and Manage Aliases:

  #	Set up aliases for common commands (e.g., alias ll='ls -l').

  #	Store aliases in ~/.bashrc and ensure they are loaded at login.
 
 4.	Configure Shell Options:
  
  #	Enable options such as noclobber (prevent overwriting files) and autocd (auto-change directory) in the shell.
Outcome:
You will learn how to configure user-specific environments, including environment variables, aliases, and shell prompts, to optimize the user experience.
________________________________________
Lab 2: Managing System-Wide Environment Settings
Objective: Learn to configure system-wide environment settings for all users.
Task:
 1.	Configure Global Environment Variables:
  
  #	Set global environment variables in /etc/environment, /etc/profile, and /etc/bash.bashrc.
 
 2.	Configure Shell Initialization Files:
  
  #	Modify /etc/profile and /etc/bash.bashrc to configure system-wide settings such as umask, PATH, and the default shell.

 3.	Control User Environment with PAM:
  
  #	Modify /etc/pam.d/common-session to ensure user-specific environment settings are correctly applied for each login session.
 
 4.	Set System-Wide Aliases:
  
  #	Create aliases in /etc/bash.bashrc for commonly used system commands (e.g., alias rm='rm -i' to prompt before deleting files).
 
 5.	Test User Sessions:

  #	Test login with multiple users to ensure that system-wide configurations are applied.
Outcome:
You will understand how to configure system-wide environment settings, ensuring that they apply to all users on the system.
________________________________________
lab 3: Managing and Configuring System Time and Locale
Objective: Learn how to manage the system’s time zone and locale settings.
Task:
 1.	Configure Time Zone:

  #	Use the timedatectl command to set the system time zone (e.g., timedatectl set-timezone America/New_York).
 
 2.	Synchronize Time with NTP:
  
  #	Configure NTP (Network Time Protocol) for time synchronization using systemctl enable ntp and verify synchronization with timedatectl.

 3.	Set Locale:
  
  #	Configure system locale using locale and localectl (e.g., localectl set-locale LANG=en_US.UTF-8).
  
  #	Test the locale setting with locale and configure the keyboard layout if needed.
 
 4.	Change Date and Time Manually:
  
  #   Use date to set the current date and time manually (useful for debugging).
 
 5.	Verify Changes:
  
  #	Ensure that the time zone and locale settings are applied by checking /etc/localtime and environment variables like LANG.
Outcome:
You will be able to manage and configure system time and locale, ensuring that your system is set up according to the correct region and time.
________________________________________
Lab 4: Configuring System PATH and Executable Search Order
Objective: Understand how to manage the system's executable search path and control command execution order.
Task:
 1.	View the Current PATH:

  #	Use echo $PATH to view the current directories listed in the system PATH.
 
 2.	Modify the PATH:
  
  #   Add directories to the PATH in /etc/profile, /etc/bash.bashrc, and ~/.bashrc to include custom executable directories.
  
  #	Test the new directory by placing an executable in a new directory and running it directly.
 
 3.	Configure Local User PATH:
  
  #	Modify ~/.bash_profile or ~/.bashrc to append directories to the user-specific PATH.
 
 4.	Ensure Proper Order of PATH:
  
  #	Ensure that custom directories are searched before system directories by placing them at the beginning of the PATH.
 
 5.	Test Command Execution Order:
  
  #	Test the execution order of commands by creating two executables with the same name in different directories.
Outcome:
You will understand how the system searches for executables and how to control the order in which directories are searched by modifying the PATH.
________________________________________
Lab 5: Configuring and Managing User Groups and Permissions
Objective: Learn how to manage user groups and file permissions to secure the system.
Task:
 1.	Create User Groups:
  
  #	Create user groups with groupadd (e.g., groupadd developers).
 
 2.	Add Users to Groups:
 
  #	Use usermod -aG groupname username to add users to a group.
 
 3.	Set File Permissions:
 
  #	Use chmod, chown, and chgrp to configure file ownership and permissions for directories and files.
 
  #	Set directory and file permissions for different users (e.g., read, write, execute) and test access.
 
 4.	Test Permissions:
   
   #	Log in as a user from different groups and test the permissions and file access to verify proper configuration.
 
 5.	Set Up Sudo Access:
  
  #	Add a user to the sudoers file to allow elevated permissions using visudo.
Outcome:
You will gain practical experience in managing user groups, setting file permissions, and securing files and directories through proper ownership and access controls.
________________________________________
Lab 6: Automating Environment Setup with Scripts
Objective: Automate environment configuration and settings using shell scripts.
Task:
 1.	Create a User Environment Setup Script:
  
  #  	Write a script that sets up environment variables, custom aliases, and modifies the prompt.
  
  #	The script should add settings to ~/.bashrc or ~/.bash_profile and apply them to the user's session.
 
 2.	Automate Software Installation:
  
  #	Write a script to install commonly used packages and software (e.g., vim, git, curl).

  #	Use package managers like apt, yum, or dnf to automate installation.
  
 3.	Configure Environment Based on User Input:

  #	Modify the script to configure different environments based on user input, such as custom editor settings or shell options.

 4.	Test and Troubleshoot:
  
  #	Test the script on different systems and ensure that the changes are applied correctly.
 
 5.	Run the Script Automatically on Login:
  
  #	Use crontab or system initialization files like /etc/rc.local to run the script automatically when a user logs in.
Outcome:
You will learn to automate the configuration of user environments, ensuring consistency across multiple systems.
________________________________________
Lab 7: Configuring System-Wide Security Settings
Objective: Configure system-wide security settings to harden the environment and secure user access.
Task:
1.	Set Up Password Policies:
 
 #	Edit /etc/login.defs to enforce password length, expiration, and complexity rules.

 #	Use chage to configure password aging for users.

2.	Limit User Logins:
 
 #	Configure the /etc/security/limits.conf file to set resource limits for users and groups (e.g., maximum number of simultaneous logins).

3.	Enable Firewall:
 
 #	Configure ufw or iptables to restrict access to the system based on IP addresses, ports, or protocols.

4.	Configure SSH Settings:
 
 #	Edit /etc/ssh/sshd_config to disable root login, set strong encryption, and limit SSH access to specific users or groups.

5.	Audit and Monitor User Access:
 
 #	Install and configure auditd for auditing user activities and access.

 #	Review logs in /var/log/auth.log and /var/log/audit/audit.log.
Outcome:
You will understand how to configure system-wide security settings to enforce strong security policies for users and services.
________________________________________
Lab 8: Managing System Resources and Limits
Objective:
Configure system resource limits for users and processes.
Task:
1.	Set Resource Limits:
 
 #	Use ulimit to set process limits for CPU time, file size, number of open files, etc.
 
 #	Modify /etc/security/limits.conf to apply limits for specific users or groups.

2.	Configure System Resource Limits:
 
 #	Use sysctl to modify system resource limits for processes (e.g., fs.file-max for the maximum number of open files).

3.	Monitor Resource Usage:
 
 #	Use tools like top, htop, and dstat to monitor resource consumption and identify processes that exceed their limits.

4.	Apply Changes Persistently:
 
 #	Ensure that changes to resource limits are applied persistently across reboots by modifying configuration files.
Outcome:
You will learn how to manage system resource usage effectively, ensuring that processes and users do not overconsume resources and that the system remains responsive.
________________________________________
Conclusion
These Linux environment management lab tasks cover a wide array of system management activities that allow you to configure user environments, manage system settings, automate environment setup, enforce security policies, and control resource usage. By completing these labs, you will gain hands-on experience in managing Linux environments, which is essential for system administration and security in real-world scenarios.
Linux Environment Management: Shell Profile Lab Tasks
This lab focuses on configuring and managing shell profiles in a Linux environment, which are critical for customizing and managing the user environment. Shell profiles are used to set environment variables, aliases, functions, and other configurations that affect the user’s shell behavior. In this lab, you will work with various shell profile files like .bashrc, .bash_profile, /etc/profile, and /etc/bash.bashrc.
Objective:
• Understand how to manage user-specific and system-wide environment settings using shell profiles.
• Learn how to configure environment variables, customize the command prompt, and define aliases and functions.
• Automate configurations for system-wide settings and user-specific preferences. Lab Tasks:
________________________________________
1. Task: Understanding Shell Profile Files
Objective:
Learn about the different profile files that control the shell environment in Linux.
• Files to Explore:
1.	/etc/profile:

 #	This file is used for system-wide environment settings. It is executed for login shells.

2.	~/.bash_profile or ~/.profile:
 
 #	These files are user-specific and executed for login shells. .bash_profile is preferred in Bash, while .profile is used in other shells.

3.	~/.bashrc:
 
 #	Executed for non-login interactive shells. It's typically used to define aliases, functions, and environment variables.

4.	/etc/bash.bashrc:
 
 #	System-wide Bash settings executed for every interactive non-login shell.
Task:
1.	Use the cat command to examine the contents of the /etc/profile, ~/.bash_profile, and ~/.bashrc files.
2.	Learn the difference between login and non-login shells.
3.	Check if the files exist, and create them if they don’t.
Outcome:
Understand how different profile files work and how they influence shell behavior.
________________________________________
2. Task: Setting Up Environment Variables
Objective: Learn to set environment variables for user-specific or system-wide configuration.
Task:
1.	Set Environment Variables for a Single User:
 
 #	Add environment variables like PATH, JAVA_HOME, or EDITOR in ~/.bash_profile or ~/.bashrc.
 
 # 	Example: Add export PATH=$PATH:/opt/custom/bin to append a custom directory to the PATH.

2.	Set System-Wide Environment Variables:
 
 #	Add environment variables to /etc/profile for all users.
 
 #	Example: export JAVA_HOME=/usr/local/java to set the Java home directory globally.

3.	Make Changes Effective:
 
 #	After editing the profile files, run source ~/.bash_profile or source ~/.bashrc to apply changes.

4.	Verify Changes:
 
 #	Use echo $VARIABLE_NAME to verify that the environment variable is set correctly.
Outcome:
Understand how to set environment variables for individual users or globally.
________________________________________
3. Task: Customizing the Bash Prompt
Objective:
Customize the bash prompt (PS1) to improve the user experience.
Task:
1.	Modify the PS1 Variable:
 
 #	Open ~/.bashrc and customize the PS1 variable to change the command prompt.
 
 #	Example: export PS1="[\u@\h \W]\$ " will show the username, hostname, and current directory.

2.	Add Colors to the Prompt:
 
 #	Use ANSI escape codes to add colors to the prompt. For example:
bash
Copy code
export PS1="[\033[01;32m]\u[\033[00m]@[\033[01;34m]\h[\033[00m]:[\033[01;33m]\w[\033[00m]$ " This will color the username, hostname, and directory in green, blue, and yellow, respectively.
3.	Add Additional Information:
 
 #	Include the current time or the exit status of the last command in the prompt.
 
 #	Example: export PS1="[\u@\h \w \$(date +'%T')]\$ " will add the time to the prompt.
Outcome:
You will have a personalized command prompt that enhances usability and gives quick access to useful information.
________________________________________
4. Task: Defining Aliases for Frequently Used Commands
Objective:
Set up aliases for commonly used commands to simplify daily tasks.
Task:
1.	Create Aliases:
 
 #	Add aliases to ~/.bashrc or /etc/bash.bashrc.
 
 #	Example: alias ll='ls -l' to make ll a shortcut for ls -l.

2.	Add Helpful Aliases:
 
 #	Set up aliases for commands like ls, cp, rm, or grep to include common options.

 #	Example:
bash
Copy code
alias rm='rm -i' # Prompt before deleting files
alias grep='grep --color=auto' # Enable color in grep results
3.	Apply the Changes:
 
 #	Run source ~/.bashrc to load the new aliases.

4.	Test Aliases:
 
 #	Use the alias to verify the command works as expected. For example, run ll and check if it lists files with long format.
Outcome:
Learn to set up aliases to simplify command-line operations.
________________________________________
5. Task: Creating Shell Functions
Objective:
Define shell functions to automate common tasks and improve workflow.
Task:
1.	Write Simple Shell Functions:
 
 #	Create simple functions in ~/.bashrc for repetitive tasks.
 
 #	Example: A function to check disk space and sort by usage:
bash
Copy code
function disk_space() {
df -h | sort -k 5 -n
}
2.	Add Parameters to Functions:
 
 #	Add parameters to functions for flexibility.

 #	Example: A function to search for a string in files:
bash
Copy code
function search_in_files() {
grep -r "$1" $2
}
3.	Apply Changes:
 
 #	Run source ~/.bashrc to load the new functions.

4.	Test the Functions:
 
 #	Test the functions by calling them from the terminal.
Outcome:
You will know how to define and use shell functions to streamline workflows.
________________________________________
6. Task: Configuring Shell Startup Behavior
Objective: Learn how to configure shell startup behavior to automatically run scripts or commands when a shell session starts.
Task:
1.	Edit ~/.bash_profile for Login Shell Behavior:
 
 #	Add commands to ~/.bash_profile that should run when a user logs in.
 
 #	Example: Automatically start a custom script:
bash
Copy code
if [ -f ~/startup.sh ]; then
. ~/startup.sh
fi
2.	Configure ~/.bashrc for Non-Login Shells:
 
 #	Ensure that ~/.bashrc runs for non-login shells. Use source ~/.bash_profile in ~/.bashrc to ensure login-related settings are applied to all sessions.

3.	Test the Configuration:
 
 #	Open a new terminal window or log in to the system and verify that the desired behavior (e.g., script execution) occurs.
Outcome:
You will learn to configure your shell’s startup behavior to run commands automatically when a user logs in or opens a new shell session.
________________________________________
7. Task: Debugging and Troubleshooting Shell Profiles
Objective:
Troubleshoot and debug issues related to shell profiles and environment settings.
Task:
1.	Identify Misconfigurations:
 
 #	Use the echo command to check environment variables like PATH, EDITOR, PS1, etc.
 
 #	Check for syntax errors in ~/.bashrc or /etc/profile by running bash -n ~/.bashrc.

2.	Log Shell Execution:
 
 #	Use set -x to trace the execution of commands in the shell profile files.
 
 #	Example: Add set -x at the beginning of ~/.bashrc to see each command as it's executed.

3.	Resolve Common Problems:

 #	Fix issues like incorrect PATH settings or problems with loading custom scripts.

4.	Check for Redundant Configuration:
 
 #	Ensure that ~/.bash_profile is not conflicting with ~/.bashrc. Typically, .bash_profile should source .bashrc to avoid duplication of configurations.
Outcome:
You will become proficient in debugging and troubleshooting shell profiles and environment configurations.
________________________________________
8. Task: System-Wide Profile Configuration
Objective: Configure system-wide profile settings for all users.
Task:
1.	Modify /etc/profile:
 
 #	Add global environment variables, such as PATH, that should apply to all users.
 
 #	Example: export PATH=$PATH:/opt/software/bin

2.	Configure /etc/bash.bashrc:

 #	Add system-wide aliases and functions that apply to all users.
 
 # 	Example: alias ls='ls --color=auto' for all users.

3.	Test with Multiple User Accounts:
 
 #	Log in as different users and verify that system-wide changes are applied.
Outcome:
You will be able to configure system-wide settings that apply to all users, which is essential for managing environments in multi-user systems.
________________________________________
Conclusion:
By completing these tasks, you will gain a solid understanding of how to manage user

