/*
 * analyser.js
 * Password strength scoring engine.
 * Uses regular expressions for character class checks and a
 * points based algorithm (additions and deductions) for the score.
 */

var PasswordAnalyser = (function () {

    // --- regex patterns ---
    var REGEX = {
        lower:    /[a-z]/g,
        upper:    /[A-Z]/g,
        digit:    /[0-9]/g,
        special:  /[^a-zA-Z0-9]/g,
        onlyLetters: /^[a-zA-Z]+$/,
        onlyDigits:  /^[0-9]+$/,
        repeat:   /(.)\1{2,}/g,          // same char 3 or more times, e.g. "aaa"
        consecLower: /[a-z]{2,}/g,
        consecUpper: /[A-Z]{2,}/g,
        consecDigit: /[0-9]{2,}/g,
        year:     /(19|20)\d{2}/          // looks like a year
    };

    // small list of very common passwords
    var COMMON = [
        'password', 'password1', '123456', '12345678', '123456789', 'qwerty',
        'abc123', 'letmein', 'monkey', 'dragon', 'iloveyou', 'admin', 'welcome',
        'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow',
        'trustno1', '111111', '000000', 'qwerty123', 'passw0rd', 'login'
    ];

    var SEQUENCES = [
        'abcdefghijklmnopqrstuvwxyz',
        '01234567890',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
    ];

    var MIN_LENGTH = 8;

    function countMatches(str, re) {
        var m = str.match(re);
        return m ? m.length : 0;
    }

    function countConsecutive(str, re) {
        // counts characters that follow a char of the same type
        var total = 0, m, i;
        m = str.match(re);
        if (!m) { return 0; }
        for (i = 0; i < m.length; i++) {
            total += m[i].length - 1;
        }
        return total;
    }

    function countSequential(str) {
        // number of 3-char runs like "abc", "123", "qwe" (and reversed)
        var lower = str.toLowerCase(), count = 0, i, j, seq, rev, part;
        for (i = 0; i < SEQUENCES.length; i++) {
            seq = SEQUENCES[i];
            rev = seq.split('').reverse().join('');
            for (j = 0; j < seq.length - 2; j++) {
                part = seq.substr(j, 3);
                if (lower.indexOf(part) !== -1) { count++; }
                part = rev.substr(j, 3);
                if (lower.indexOf(part) !== -1) { count++; }
            }
        }
        return count;
    }

    function isCommon(str) {
        var lower = str.toLowerCase();
        // also catch simple leetspeak like p@ssw0rd
        var normal = lower.replace(/@/g, 'a').replace(/0/g, 'o')
                          .replace(/1/g, 'i').replace(/3/g, 'e')
                          .replace(/\$/g, 's');
        for (var i = 0; i < COMMON.length; i++) {
            if (lower === COMMON[i] || normal === COMMON[i]) {
                return true;
            }
        }
        return false;
    }

    function charsetSize(r) {
        var size = 0;
        if (r.lower > 0)   { size += 26; }
        if (r.upper > 0)   { size += 26; }
        if (r.digit > 0)   { size += 10; }
        if (r.special > 0) { size += 33; }
        return size;
    }

    function crackTime(pwd, r) {
        // brute force estimate at 10 billion guesses / sec (offline attack)
        var size = charsetSize(r);
        if (size === 0) { return '-'; }
        if (r.common) { return 'Instantly'; }

        var entropy = pwd.length * (Math.log(size) / Math.LN2);
        var seconds = Math.pow(2, entropy) / 2 / 1e10;

        if (seconds < 1)        { return 'Instantly'; }
        if (seconds < 60)       { return Math.round(seconds) + ' seconds'; }
        if (seconds < 3600)     { return Math.round(seconds / 60) + ' minutes'; }
        if (seconds < 86400)    { return Math.round(seconds / 3600) + ' hours'; }
        if (seconds < 31536000) { return Math.round(seconds / 86400) + ' days'; }
        var years = seconds / 31536000;
        if (years < 1000)       { return Math.round(years) + ' years'; }
        if (years < 1e6)        { return Math.round(years / 1000) + 'k years'; }
        return 'Centuries';
    }

    function getLabel(score) {
        if (score < 20) { return { text: 'Very Weak', css: 'danger' }; }
        if (score < 40) { return { text: 'Weak', css: 'danger' }; }
        if (score < 60) { return { text: 'Fair', css: 'warning' }; }
        if (score < 80) { return { text: 'Strong', css: 'info' }; }
        return { text: 'Very Strong', css: 'success' };
    }

    /*
     * analyse(pwd) -> result object
     */
    function analyse(pwd) {
        var r = {
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
            r.crack = '-';
            return r;
        }

        var len = pwd.length, score = 0, pts;

        // ---------- validation rules ----------
        r.rules.length  = len >= MIN_LENGTH;
        r.rules.lower   = r.lower > 0;
        r.rules.upper   = r.upper > 0;
        r.rules.digit   = r.digit > 0;
        r.rules.special = r.special > 0;
        r.rules.longer  = len >= 12;

        function add(name, count, points) {
            r.breakdown.push({ name: name, count: count, points: points });
            score += points;
        }

        // ---------- additions ----------
        add('Number of characters', len, len * 4);

        if (r.upper > 0 && r.upper < len) {
            add('Uppercase letters', r.upper, (len - r.upper) * 2);
        }
        if (r.lower > 0 && r.lower < len) {
            add('Lowercase letters', r.lower, (len - r.lower) * 2);
        }
        if (r.digit > 0 && r.digit < len) {
            add('Numbers', r.digit, r.digit * 4);
        }
        if (r.special > 0) {
            add('Symbols', r.special, r.special * 6);
        }

        // middle numbers/symbols
        var middle = pwd.substr(1, len - 2);
        var midCount = countMatches(middle, /[^a-zA-Z]/g);
        if (midCount > 0) {
            add('Middle numbers or symbols', midCount, midCount * 2);
        }

        // requirements met
        var met = 0;
        if (r.rules.length)  { met++; }
        if (r.rules.lower)   { met++; }
        if (r.rules.upper)   { met++; }
        if (r.rules.digit)   { met++; }
        if (r.rules.special) { met++; }
        if (r.rules.length && met >= 4) {
            add('Requirements met', met, met * 2);
        }

        // ---------- deductions ----------
        if (REGEX.onlyLetters.test(pwd)) {
            add('Letters only', len, -len);
        }
        if (REGEX.onlyDigits.test(pwd)) {
            add('Numbers only', len, -len);
        }

        var rep = countMatches(pwd, REGEX.repeat);
        if (rep > 0) {
            add('Repeated characters (aaa)', rep, -(rep * 6));
        }

        pts = countConsecutive(pwd, REGEX.consecUpper);
        if (pts > 0) { add('Consecutive uppercase', pts, -(pts * 2)); }
        pts = countConsecutive(pwd, REGEX.consecLower);
        if (pts > 0) { add('Consecutive lowercase', pts, -(pts * 2)); }
        pts = countConsecutive(pwd, REGEX.consecDigit);
        if (pts > 0) { add('Consecutive numbers', pts, -(pts * 2)); }

        var seq = countSequential(pwd);
        if (seq > 0) {
            add('Sequences (abc, 123, qwe)', seq, -(seq * 3));
        }

        if (REGEX.year.test(pwd)) {
            add('Contains a year', 1, -5);
        }

        r.common = isCommon(pwd);
        if (r.common) {
            add('Common password', 1, -score); // wipe it out
        }

        // clamp
        if (score < 0)   { score = 0; }
        if (score > 100) { score = 100; }
        r.score = score;
        r.label = getLabel(score);
        r.crack = crackTime(pwd, r);

        // ---------- feedback ----------
        var fb = r.feedback;
        if (r.common) {
            fb.push({ type: 'warn', msg: 'This is one of the most common passwords. Do not use it.' });
        }
        if (!r.rules.length) {
            fb.push({ type: 'warn', msg: 'Use at least ' + MIN_LENGTH + ' characters.' });
        }
        if (!r.rules.upper) { fb.push({ type: 'warn', msg: 'Add some uppercase letters.' }); }
        if (!r.rules.lower) { fb.push({ type: 'warn', msg: 'Add some lowercase letters.' }); }
        if (!r.rules.digit) { fb.push({ type: 'warn', msg: 'Add a number.' }); }
        if (!r.rules.special) { fb.push({ type: 'warn', msg: 'Add a symbol like ! @ # $ %.' }); }
        if (rep > 0) { fb.push({ type: 'warn', msg: 'Avoid repeating the same character.' }); }
        if (seq > 0) { fb.push({ type: 'warn', msg: 'Avoid sequences like "abc", "123" or "qwerty".' }); }
        if (REGEX.year.test(pwd)) { fb.push({ type: 'warn', msg: 'Years (like birth years) are easy to guess.' }); }
        if (r.rules.length && !r.rules.longer) {
            fb.push({ type: 'info', msg: 'Tip: 12 or more characters makes it much harder to crack.' });
        }
        if (fb.length === 0) {
            fb.push({ type: 'good', msg: 'Great password! Just remember not to reuse it on other sites.' });
        }

        return r;
    }

    return {
        analyse: analyse
    };

})();
