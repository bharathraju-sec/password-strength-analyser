const PasswordAnalyser = require('../js/analyser');

const analyse = (pwd) => PasswordAnalyser.analyse(pwd);

describe('PasswordAnalyser', () => {

    test('empty password scores 0', () => {
        const r = analyse('');
        expect(r.score).toBe(0);
        expect(r.breakdown).toHaveLength(0);
    });

    test('common passwords score 0', () => {
        ['password', 'qwerty', 'abc123', 'letmein'].forEach((p) => {
            expect(analyse(p).score).toBe(0);
            expect(analyse(p).common).toBe(true);
        });
    });

    test('leetspeak versions of common passwords are caught', () => {
        expect(analyse('p@ssw0rd').common).toBe(true);
        expect(analyse('p@ssw0rd').score).toBe(0);
    });

    test('complexity rules are detected with regex', () => {
        const r = analyse('Abc!2xyzWq');
        expect(r.rules).toEqual({
            length: true, lower: true, upper: true,
            digit: true, special: true, longer: false
        });
    });

    test('short password fails the length rule', () => {
        const r = analyse('Ab1!');
        expect(r.rules.length).toBe(false);
        expect(r.feedback.some((f) => f.msg.includes('at least 8'))).toBe(true);
    });

    test('repeated characters are penalised', () => {
        const r = analyse('Kaaa9!mzQ');
        expect(r.breakdown.find((b) => b.name.startsWith('Repeated')).points).toBeLessThan(0);
    });

    test('sequences are penalised', () => {
        const r = analyse('Xabc!7Pq');
        expect(r.breakdown.some((b) => b.name.startsWith('Sequences'))).toBe(true);
    });

    test('years are penalised', () => {
        expect(analyse('Summer2019!').breakdown.some((b) => b.name === 'Contains a year')).toBe(true);
    });

    test('long mixed password is Very Strong', () => {
        const r = analyse('c0rrect-H0rse!Battery');
        expect(r.score).toBe(100);
        expect(r.label.text).toBe('Very Strong');
    });

    test('entropy and keyspace are calculated from the charset', () => {
        // lower + upper + digit + special = 26 + 26 + 10 + 33 = 95 symbols
        const r = analyse('Ab1!Ab1!');
        expect(r.keyspace).toBe('95^8');
        expect(r.entropy).toBe(Math.round(8 * Math.log2(95)));
    });

    test('crack time is given for every attack scenario', () => {
        const r = analyse('Tr0ub4dor&3');
        expect(r.attacks).toHaveLength(PasswordAnalyser.ATTACKS.length);
        expect(r.crack).toBe(r.attacks[r.attacks.length - 1].time);
        // a throttled online attack can never be faster than an offline one
        expect(r.attacks[0].time).not.toBe('Instantly');
    });

    test('common passwords are cracked instantly in every scenario', () => {
        analyse('letmein').attacks.forEach((a) => expect(a.time).toBe('Instantly'));
    });

    test('each breakdown line records the rule or regex used', () => {
        const r = analyse('Kaaa9!mzQ');
        expect(r.breakdown.every((b) => typeof b.rule === 'string' && b.rule.length > 0)).toBe(true);
        expect(r.breakdown.find((b) => b.name.startsWith('Repeated')).rule).toBe('/(.)\\1{2,}/');
    });

    test('score is always between 0 and 100', () => {
        ['a', 'aaaaaaa', 'Zx9!Zx9!Zx9!Zx9!Zx9!Zx9!', '12345'].forEach((p) => {
            const { score } = analyse(p);
            expect(score).toBeGreaterThanOrEqual(0);
            expect(score).toBeLessThanOrEqual(100);
        });
    });
});
