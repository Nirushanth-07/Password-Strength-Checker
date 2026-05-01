import hashlib
import requests
import math

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def have_i_been_pwned(password):
    sha1_password = hashlib.sha1(password.encode('utf-8'))
    hashed_pwd = sha1_password.hexdigest().upper()
    
    url = "https://api.pwnedpasswords.com/range/" + hashed_pwd[:5]
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            pwd_list = response.text.splitlines()
            found = 0
            for i in pwd_list:
                pwd = i.split(":")
                if hashed_pwd[:5] + pwd[0] == hashed_pwd:
                    print(f"{RED}This password has been seen {pwd[1]} times before in data breaches!{RESET}")
                    found = 1
                    break
            if not found:
                print(f"{GREEN}This password has not been seen in data breaches!{RESET}")

        else:
            print("Error:", response.status_code)
            return None
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None

def entropy_calculation(password):
    print(f"Password Length: {len(password)}")
    found_lowercase = False
    found_uppercase = False
    found_digits = False
    found_symbol = False
    R = 0

    for i in range(len(password)):
        if ord(password[i]) > 96 and ord(password[i]) < 123 and not found_lowercase:
            found_lowercase = True
            R += 26
            print(f"Lowercase Letter: {GREEN}Found{RESET}")
        elif ord(password[i]) > 64 and ord(password[i]) < 91 and not found_uppercase:
            found_uppercase = True
            R += 26
            print(f"Uppercase Letter: {GREEN}Found{RESET}")
        elif ord(password[i]) > 47 and ord(password[i]) < 58 and not found_digits:
            found_digits = True
            R += 10
            print(f"Digits: {GREEN}Found{RESET}")

        elif ((ord(password[i]) > 31 and ord(password[i]) < 48) or (ord(password[i]) > 57 and ord(password[i]) < 65) or 
        (ord(password[i]) > 90 and ord(password[i]) < 97) or (ord(password[i]) > 122 and ord(password[i]) < 127))and not found_symbol:
            found_symbol = True
            R += 33
            print(f"Symbol: {GREEN}Found{RESET}")

        
        if found_digits and found_lowercase and found_symbol and found_uppercase:
            break

    if not found_uppercase:
        print(f"Uppercase Letter: {RED}Not Found{RESET}")
    if not found_lowercase:
        print(f"Lowercase Letter: {RED}Not Found{RESET}")
    if not found_digits:
        print(f"Digits: {RED}Not Found{RESET}")
    if not found_symbol:
        print(f"Symbols: {RED}Not Found{RESET}")

    entropy = len(password) * math.log2(R)

    if entropy < 32:
        return f"{RED}Very Weak{RESET}"
    elif entropy < 56:
        return f"{RED}Weak{RESET}"
    elif entropy < 81:
        return f"{YELLOW}Medium{RESET}"
    elif entropy < 112:
        return f"{GREEN}Strong{RESET}"
    else:
        return f"{GREEN}Excellent{RESET}"
    


if __name__ == "__main__":

    banner = """
*************************************
*        PASSWORD CHECKER v1.0      *
*************************************
                 _
               _|_|_
               (o o)
           ooO--(_)--Ooo
"""

    print(banner)

    
    print("Enter The Password: ", end="")
    password = input()
    
    print("\n")
    print("\nPassword Entropy Check: ", entropy_calculation(password))

    print("\nHave I Been Pwned Check: ", end="")
    have_i_been_pwned(password)
    print("\n")