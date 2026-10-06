/**
 * analyser.js
 * Password strength scoring engine.
 * Uses regular expressions for character class checks and a
 * points based algorithm (additions and deductions) for the score.
 */

const PasswordAnalyser = (() => {

    // --- regex patterns ---
    const REGEX = {
        lower: /[a-z]/g,
        upper: /[A-Z]/g,
        digit: /[0-9]/g,
        special: /[^a-zA-Z0-9]/g,
        onlyLetters: /^[a-zA-Z]+$/,
        onlyDigits: /^[0-9]+$/,
        repeat: /(.)\1{2,}/g,          // same char 3 or more times, e.g. "aaa"
        consecLower: /[a-z]{2,}/g,
        consecUpper: /[A-Z]{2,}/g,
        consecDigit: /[0-9]{2,}/g,
        year: /(19|20)\d{2}/           // looks like a year
    };

    // small list of very common passwords
    const COMMON = new Set([
        'password', 'password1', '123456', '12345678', '123456789', 'qwerty',
        'abc123', 'letmein', 'monkey', 'dragon', 'iloveyou', 'admin', 'welcome',
        'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow',
        'trustno1', '111111', '000000', 'qwerty123', 'passw0rd', 'login'
    ]);

    const SEQUENCES = [
        'abcdefghijklmnopqrstuvwxyz',
        '01234567890',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
    ];

    const LEET = { '@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's' };

    const MIN_LENGTH = 8;

    // guessing speed for common attack scenarios (guesses per second)
    const ATTACKS = [
        { name: 'Online attack, throttled (100 / hour)', rate: 100 / 3600 },
        { name: 'Online attack, not throttled', rate: 10 },
        { name: 'Offline attack, slow hash (bcrypt)', rate: 1e4 },
        { name: 'Offline attack, fast hash (MD5 on GPUs)', rate: 1e10 }
    ];

    const countMatches = (str, re) => (str.match(re) || []).length;

    // counts characters that follow a char of the same type
    const countConsecutive = (str, re) =>
        (str.match(re) || []).reduce((total, run) => total + run.length - 1, 0);

    // number of 3-char runs like "abc", "123", "qwe" (and reversed)
    const countSequential = (str) => {
        const lower = str.toLowerCase();
        let count = 0;
        for (const seq of SEQUENCES) {
            const rev = [...seq].reverse().join('');
            for (let i = 0; i < seq.length - 2; i++) {
                if (lower.includes(seq.substr(i, 3))) count++;
                if (lower.includes(rev.substr(i, 3))) count++;
            }
        }
        return count;
    };

    // also catches simple leetspeak like p@ssw0rd
    const isCommon = (str) => {
        const lower = str.toLowerCase();
        const normal = lower.replace(/[@013$]/g, (c) => LEET[c]);
        return COMMON.has(lower) || COMMON.has(normal);
    };

    const charsetSize = ({ lower, upper, digit, special }) =>
        (lower > 0 ? 26 : 0) + (upper > 0 ? 26 : 0) +
        (digit > 0 ? 10 : 0) + (special > 0 ? 33 : 0);

    // entropy in bits = length * log2(charset size)
    const entropyBits = (length, size) => (size > 0 ? length * Math.log2(size) : 0);

    const formatDuration = (seconds) => {
        if (seconds < 1) return 'Instantly';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        const years = seconds / 31536000;
        if (years < 1000) return `${Math.round(years)} years`;
        if (years < 1e6) return `${Math.round(years / 1000)}k years`;
        return 'Centuries';
    };

    // brute force: on average half of the keyspace (2^entropy) is searched
    const crackTimes = (bits, common) => ATTACKS.map(({ name, rate }) => ({
        name,
        rate,
        time: common ? 'Instantly' : formatDuration(2 ** bits / 2 / rate)
    }));

    const formatRate = (rate) => {
        if (rate < 1) return `${Math.round(rate * 3600)} / hour`;
        return rate >= 1e6 ? rate.toExponential(0).replace('e+', ' x 10^') : String(rate);
    };

    const getLabel = (score) => {
        if (score < 20) return { text: 'Very Weak', css: 'danger' };
        if (score < 40) return { text: 'Weak', css: 'danger' };
        if (score < 60) return { text: 'Fair', css: 'warning' };
        if (score < 80) return { text: 'Strong', css: 'info' };
        return { text: 'Very Strong', css: 'success' };
    };

    /**
     * analyse(pwd) -> result object
     */
    const analyse = (pwd = '') => {
        const r = {
            length: pwd.length,
            lower: countMatches(pwd, REGEX.lower),
            upper: countMatches(pwd, REGEX.upper),
            digit: countMatches(pwd, REGEX.digit),
            special: countMatches(pwd, REGEX.special),
            rules: {},
            breakdown: [],
            feedback: [],
            score: 0
        };

        if (pwd.length === 0) {
            r.label = { text: '-', css: 'danger' };
            r.entropy = 0;
            r.keyspace = '-';
            r.attacks = ATTACKS.map(({ name, rate }) => ({ name, rate, time: '-' }));
            r.crack = '-';
            return r;
        }

        const len = pwd.length;
        let score = 0;

        // rule = the regex (or other check) that produced this line
        const add = (name, count, points, rule) => {
            r.breakdown.push({ name, count, points, rule });
            score += points;
        };
        const re = (regex) => `/${regex.source}/`;

        // ---------- validation rules ----------
        r.rules = {
            length: len >= MIN_LENGTH,
            lower: r.lower > 0,
            upper: r.upper > 0,
            digit: r.digit > 0,
            special: r.special > 0,
            longer: len >= 12
        };

        // ---------- additions ----------
        add('Number of characters', len, len * 4, 'length');

        if (r.upper > 0 && r.upper < len) add('Uppercase letters', r.upper, (len - r.upper) * 2, re(REGEX.upper));
        if (r.lower > 0 && r.lower < len) add('Lowercase letters', r.lower, (len - r.lower) * 2, re(REGEX.lower));
        if (r.digit > 0 && r.digit < len) add('Numbers', r.digit, r.digit * 4, re(REGEX.digit));
        if (r.special > 0) add('Symbols', r.special, r.special * 6, re(REGEX.special));

        // middle numbers/symbols
        const MIDDLE = /[^a-zA-Z]/g;
        const midCount = countMatches(pwd.substr(1, len - 2), MIDDLE);
        if (midCount > 0) add('Middle numbers or symbols', midCount, midCount * 2, re(MIDDLE));

        // requirements met
        const { length, lower, upper, digit, special } = r.rules;
        const met = [length, lower, upper, digit, special].filter(Boolean).length;
        if (length && met >= 4) add('Requirements met', met, met * 2, 'rules');

        // ---------- deductions ----------
        if (REGEX.onlyLetters.test(pwd)) add('Letters only', len, -len, re(REGEX.onlyLetters));
        if (REGEX.onlyDigits.test(pwd)) add('Numbers only', len, -len, re(REGEX.onlyDigits));

        const rep = countMatches(pwd, REGEX.repeat);
        if (rep > 0) add('Repeated characters (aaa)', rep, -(rep * 6), re(REGEX.repeat));

        const consecutive = [
            ['Consecutive uppercase', REGEX.consecUpper],
            ['Consecutive lowercase', REGEX.consecLower],
            ['Consecutive numbers', REGEX.consecDigit]
        ];
        for (const [name, regex] of consecutive) {
            const n = countConsecutive(pwd, regex);
            if (n > 0) add(name, n, -(n * 2), re(regex));
        }

        const seq = countSequential(pwd);
        if (seq > 0) add('Sequences (abc, 123, qwe)', seq, -(seq * 3), 'sequence scan');

        const hasYear = REGEX.year.test(pwd);
        if (hasYear) add('Contains a year', 1, -5, re(REGEX.year));

        r.common = isCommon(pwd);
        if (r.common) add('Common password', 1, -score, 'dictionary'); // wipe it out

        r.score = Math.min(100, Math.max(0, score));
        r.label = getLabel(r.score);

        // ---------- entropy + crack time ----------
        const size = charsetSize(r);
        r.entropy = Math.round(entropyBits(len, size));
        r.keyspace = `${size}^${len}`;
        r.attacks = crackTimes(entropyBits(len, size), r.common);
        r.crack = r.attacks[r.attacks.length - 1].time;

        // ---------- feedback ----------
        const warn = (msg) => r.feedback.push({ type: 'warn', msg });

        if (r.common) warn('This is one of the most common passwords. Do not use it.');
        if (!r.rules.length) warn(`Use at least ${MIN_LENGTH} characters.`);
        if (!r.rules.upper) warn('Add some uppercase letters.');
        if (!r.rules.lower) warn('Add some lowercase letters.');
        if (!r.rules.digit) warn('Add a number.');
        if (!r.rules.special) warn('Add a symbol like ! @ # $ %.');
        if (rep > 0) warn('Avoid repeating the same character.');
        if (seq > 0) warn('Avoid sequences like "abc", "123" or "qwerty".');
        if (hasYear) warn('Years (like birth years) are easy to guess.');
        if (r.rules.length && !r.rules.longer) {
            r.feedback.push({ type: 'info', msg: 'Tip: 12 or more characters makes it much harder to crack.' });
        }
        if (r.feedback.length === 0) {
            r.feedback.push({ type: 'good', msg: 'Great password! Just remember not to reuse it on other sites.' });
        }

        return r;
    };

    return { analyse, formatRate, ATTACKS };

})();

// allow unit tests (Node / Jest) to import the engine
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PasswordAnalyser;
}
