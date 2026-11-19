# Password Strength Analyser

A client-side web app that checks how strong a password is while you type.
It uses regular expressions, validation rules and a points-based scoring algorithm.

## Features

- **Real-time feedback**: the score, meter and tips update on every keystroke
- **Complexity rules** (regex based): length, lowercase, uppercase, digits, symbols
- **Scoring algorithm**: points are added for length and character variety and
  taken away for weak patterns:
  - letters only / numbers only
  - repeated characters (`aaa`)
  - consecutive characters of the same type
  - sequences (`abc`, `123`, `qwerty`)
  - years (`1995`, `2019`)
  - common passwords from a dictionary, including simple leetspeak (`p@ssw0rd`)
- **Entropy and keyspace**: entropy in bits (`length x log2(charset size)`) and keyspace
  size (e.g. 95<sup>11</sup>)
- **Time to crack by attack type**: average brute-force time for four attack scenarios
  (throttled online attack, unthrottled online attack, offline attack on a slow bcrypt hash,
  offline attack on a fast hash with GPUs). Common passwords fall to a dictionary attack instantly
- **Score breakdown** table that shows how each check affected the score and the exact
  regular expression (or rule) behind it
- Show/Hide password toggle
- Nothing is sent to a server

## Tech Stack

- HTML5, CSS3 (custom properties)
- JavaScript (ES6+, no frameworks)
- Bootstrap 4.3
- Jest 29 (unit tests, run in GitHub Actions on every push)

## Academic Context

Mini project for **B.Tech (Computer Science & Engineering)**, Himalayan University, Itanagar.
Subjects from the B.Tech CSE scheme that this project applies:

| Code | Subject | Where it is used in this project |
|---|---|---|
| 402 | Formal Language and Automata Theory | Regular expressions for every complexity rule and weak-pattern check (repeats, runs, years), shown next to each score line |
| 401 | Discrete Mathematical Structures | Keyspace size (charset^length), entropy in bits (log2), average search = half the keyspace |
| 305 | Data Structures with C | Hash set lookup for the common-password dictionary, scanning keyboard/alphabet sequences |
| 306 | Web Technology | Real-time DOM updates on input events, HTML5 forms, CSS3, Bootstrap grid |
| 604 | Software Engineering | Separate scoring engine and UI modules, unit tests with Jest |
| 804-E | Cyber Crime and Laws (Elective III) | Dictionary / leetspeak attack detection, crack time for online and offline attack scenarios |

## Project Structure

```
password-strength-analyser/
├── index.html
├── css/
│   └── style.css
├── js/
│   ├── analyser.js   # scoring engine (regex checks, rules, score)
│   └── app.js        # DOM / UI updates
├── tests/
│   └── analyser.test.js
└── package.json
```

## How to Run

Open `index.html` in any modern browser. You don't need to install anything.

## Running Tests

```
npm ci
npm test
```

## Scoring Summary

| Check                      | Points            |
|----------------------------|-------------------|
| Number of characters       | +(n * 4)          |
| Uppercase letters          | +((len - n) * 2)  |
| Lowercase letters          | +((len - n) * 2)  |
| Numbers                    | +(n * 4)          |
| Symbols                    | +(n * 6)          |
| Middle numbers/symbols     | +(n * 2)          |
| Requirements met           | +(n * 2)          |
| Letters only / Numbers only| -n                |
| Repeated characters        | -(n * 6)          |
| Consecutive same type      | -(n * 2)          |
| Sequences                  | -(n * 3)          |
| Contains a year            | -5                |
| Common password            | score set to 0    |

The final score is clamped to 0-100:
Very Weak (<20), Weak (<40), Fair (<60), Strong (<80), Very Strong (80+).

## Crack Time Model

```
charset size  = 26 (a-z) + 26 (A-Z) + 10 (0-9) + 33 (symbols), only for the types used
entropy       = length x log2(charset size)          bits
average time  = 2^entropy / 2 / guesses per second
```

| Attack scenario                          | Guesses / second |
|------------------------------------------|------------------|
| Online attack, throttled                 | 100 / hour       |
| Online attack, not throttled             | 10               |
| Offline attack, slow hash (bcrypt)       | 10,000           |
| Offline attack, fast hash (MD5 on GPUs)  | 10^10            |

## Limitations

- Entropy here is a search-space estimate based on the character types used. It assumes every character is chosen at random, which real passwords rarely are.
- Predictable, personal or reused passwords can be much weaker than their score suggests. The dictionary check covers only a small list of common passwords.
- Crack times are averages for brute force under the assumed guess rates. Real times depend on the hash algorithm and its parameters, rate limiting, account lockout and the attacker's hardware.
- The score is guidance for choosing a stronger password, not a security guarantee.
