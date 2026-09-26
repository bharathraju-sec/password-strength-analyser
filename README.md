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
  - years (`1995`, `2014`)
  - common passwords from a dictionary, including simple leetspeak (`p@ssw0rd`)
- **Estimated crack time** based on charset size and length (brute force at 10^10 guesses/sec)
- **Score breakdown** table that shows how each check affected the score
- Show/Hide password toggle
- Nothing is sent to a server

## Tech Stack

- HTML5, CSS3
- JavaScript
- jQuery 1.11
- Bootstrap 3.1

## Project Structure

```
password-strength-analyser/
├── index.html
├── css/
│   └── style.css
└── js/
    ├── analyser.js   # scoring engine (regex checks, rules, score)
    └── app.js        # DOM / UI updates
```

## How to Run

Open `index.html` in any browser. You don't need to install anything.

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
