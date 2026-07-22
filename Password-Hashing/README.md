# Password Hashing and Salting Security Demo

This project demonstrates why password storage methods are important using a synthetic dataset with 500 usernames and passwords.

The project compares three different password storage methods:

- SHA-256
- Salted SHA-256
- bcrypt

and measures the security and the performance of each method.

## Purpose

Password databases frequently are stolen, and if an attacker gets ahold of one of these password databases, the password storage method determines how difficult it is to recover the original passwords.

This project shows two separate security problems:

1. The system must not generate the same hash for users who have the same password.
2. The system must make password guessing slow and expensive.

A unique salt solves the first problem, while a slow password hashing algorithm, such as bcrypt, solves the second problem.

## Project Tasks

The program works in the following order:

1. Load a synthetic dataset with 500 usernames and passwords.
2. Hash each password with SHA-256.
3. Show that identical passwords produce identical hashes.
4. Generate one cryptographically random salt for each user with Python's `secrets` module.
5. Hash each password again with SHA-256 and its unique salt.
6. Show that duplicate passwords no longer produce duplicate hashes.
7. Hash each password with bcrypt.
8. Measure the execution time for each method.

## Results

The following results are from one test with 500 passwords.

| Method | Time for 500 Hashes | Result |
|---------|--------------------:|--------|
| SHA-256 | ~0.001–0.002 s | Identical passwords generate identical hashes. |
| Salted SHA-256 | ~0.003–0.004 s | Each hash is unique because each password uses a different salt. |
| bcrypt | ~100 s | About 20,000-30,000 times slower than SHA-256. |

## Conclusions

A salt prevents duplicate passwords from producing the same hash, but does **not** stop an attacker from guessing passwords if the attacker already has the salt and the hash.

bcrypt is intentionally slow, making password guessing more expensive.

The comparison times used in this experiment were calculated with standard Python code on one CPU. However, an attacker may use GPU hardware to accelerate this process and  can calculate billions of SHA-256 hashes each second. Because of this, SHA-256 is not suitable for password storage, even when it uses a unique salt.

## Run the Program

Install the required packages.

```bash
pip install -r requirements.txt
```

Run the program.

```bash
python password_security_demo.py
```

## Requirements

The program requires the file `synthetic_userpass.csv`, but is provided to you. The provided file contains the columns:

- `username`
- `password`

## Possible Improvements

This project was a very basic and straightforward task, but can be improved in the following ways:
- Test bcrypt with different cost factors and compare the execution time.
- Add a dictionary attack or a brute-force attack to measure password recovery time for each method.
- Compare bcrypt with Argon2, which is the recommended password hashing algorithm for new systems.