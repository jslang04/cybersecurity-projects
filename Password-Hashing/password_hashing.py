"""
Password Hashing and Salting Demonstration

This program demonstrates the differences between unsalted hashing, salted
hashing, and bcrypt password hashing using a synthetic dataset of usernames
and passwords.

The program performs the following tasks:
    1. Loads user credentials from the provided username/password file.
    2. Counts the number of unique usernames and passwords to identify
       duplicate passwords.
    3. Generates SHA-256 hashes for each password and demonstrates that
       identical passwords produce identical hashes.
    4. Generates a unique random salt for each user and creates salted
       SHA-256 hashes, showing that duplicate passwords no longer produce
       identical hashes.
    5. Generates bcrypt password hashes using a unique salt and an adaptive
       work factor.
    6. Measures and compares the execution time of SHA-256 hashing, salted
       SHA-256 hashing, and bcrypt to illustrate the computational cost of
       secure password hashing.

This script highlights why password salting is necessary to prevent identical
passwords from producing identical hashes and why bcrypt is preferred for
password storage due to its intentionally slow, adaptive hashing algorithm,
which significantly reduces the effectiveness of brute-force and dictionary
attacks.

Dependencies:
    - pandas
    - hashlib
    - secrets
    - time
    - bcrypt

Input:
    synthetic_userpass.csv
        A CSV file containing the following columns:
            - username
            - password

Output:
    Console output showing:
        - Counts of unique usernames, passwords, hashes, and salted hashes
        - Verification that duplicate passwords produce duplicate SHA-256
          hashes
        - Confirmation that salted hashes are unique
        - Timing comparisons between SHA-256, salted SHA-256, and bcrypt
"""

import pandas as pd
import hashlib
import secrets
import time
import bcrypt


def load_data():
    user = pd.read_csv("synthetic_userpass.csv")
    return user


def print_uniques(user):
    #function confirms there are duplicate passwords by showing unique passwords < unique usernames
    print(f"Unique usernames: {user['username'].nunique()}")
    print(f"Unique passwords: {user['password'].nunique()}")


def hash_passwords(user):
    #This function records how long it takes to hash each password and proves that passwords and hashes are one-to-one, so two users with the same password would have the same hash. 
    hash_start = time.time()
    user['hash'] = user.apply(lambda row: hashlib.sha256(row['password'].encode('utf-8')).hexdigest(), axis=1)
    hash_end = time.time()

    print(f"Unique hashes: {user['hash'].nunique()}")

    pass_groups = user.groupby('password')['username'].apply(list).to_dict()
    pass_duplicates = {k: v for k, v in pass_groups.items() if len(v) > 1} #provides a dictionary where the key is the password and the values is a list of users. Filtered to show only passwords that are shared among users

    hash_groups = user.groupby('hash')['username'].apply(list).to_dict()
    hash_duplicates = {k: v for k, v in hash_groups.items() if len(v) > 1} #same as the pass_duplicates but for the hash values. Used to show that hases are one-to-one
    print(f"Are the password duplicates the same users as the hash duplicates? {sorted(pass_duplicates.values()) == sorted(hash_duplicates.values())}") #Confirms that the hashes are one-to-one with the passwords, further showing the need for salting

    return hash_start, hash_end


def salted_hash_passwords(user):
    #This function records the time it takes to adda a salt column, concatenate the salt and the password, then hash it. This proves that the salt generates 0 identical hashes, showing the importance of salt.
    salt_start = time.time()
    user['salt'] = user.apply(lambda row: secrets.token_hex(16), axis=1) 
    user['salted_hash'] = user.apply(lambda row: hashlib.sha256(row['password'].encode('utf-8') + row['salt'].encode('utf-8')).hexdigest(),axis=1)
    salt_end = time.time()

    salted_hash_groups = user.groupby('salted_hash')['username'].apply(list).to_dict()
    salted_hash_duplicates = {k: v for k, v in salted_hash_groups.items() if len(v) > 1} #Same idea as pass_duplicates and hash_duplicates
    print(f"Duplicated salted hashes: {salted_hash_duplicates}") #Should be 0, showing that salting ensures that no two hashes are the same

    return salt_start, salt_end


def bcrypt_passwords(user):
    #This function records the time it takes to hash and salt passwords with bcrypt.
    bcrypt_start = time.time()
    user['bcrypt'] = user.apply(lambda row: bcrypt.hashpw(row['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), axis=1) 
    bcrypt_end = time.time()

    return bcrypt_start, bcrypt_end


def print_timings(hash_start, hash_end, salt_start, salt_end, bcrypt_start, bcrypt_end):
    #Output function to print the time to hash each password with each different method, which in turn shows the effectiveness against brute-force and dictionary attacks
    print(f"Hash time: {hash_end - hash_start:.6f} seconds")
    print(f"Salted hash time: {salt_end - salt_start:.6f} seconds")
    print(f"bcrypt time: {bcrypt_end - bcrypt_start:.6f} seconds") #this time should be significantly longer than the other two times, which is important because it can drop a potential attacker's guess rate from a billion/sec to a few hundred/sec, a brute-force or dictionary attack that would've taken minutes now takes years
    print(f"bcrypt is {(bcrypt_end-bcrypt_start)/(hash_end-hash_start):,.0f} times slower than the hash time")

if __name__ == "__main__":
    user = load_data()

    print_uniques(user)

    hash_start, hash_end = hash_passwords(user)
    salt_start, salt_end = salted_hash_passwords(user)
    bcrypt_start, bcrypt_end = bcrypt_passwords(user)

    print_timings(
        hash_start,
        hash_end,
        salt_start,
        salt_end,
        bcrypt_start,
        bcrypt_end,
    )