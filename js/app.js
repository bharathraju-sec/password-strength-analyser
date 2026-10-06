/**
 * app.js
 * Hooks the analyser up to the page and updates the UI in real time.
 */

document.addEventListener('DOMContentLoaded', () => {

    const $ = (sel) => document.querySelector(sel);

    const pwd = $('#password');
    const toggleBtn = $('#toggleBtn');
    const meter = $('#meter');
    const METER_CLASSES = ['bg-danger', 'bg-warning', 'bg-info', 'bg-success'];

    const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));

    const render = (result) => {
        const empty = result.length === 0;

        // meter
        meter.classList.remove(...METER_CLASSES);
        meter.classList.add(`bg-${result.label.css}`);
        meter.style.width = `${result.score}%`;

        // stats
        $('#scoreVal').textContent = result.score;
        const strength = $('#strengthVal');
        strength.textContent = result.label.text;
        strength.className = `stat-value stat-small text-${result.label.css}`;
        $('#entropyVal').textContent = empty ? '-' : `${result.entropy} bits`;
        $('#keyspaceVal').innerHTML = empty
            ? '-'
            : result.keyspace.replace(/\^(\d+)/, '<sup>$1</sup>');

        // crack time per attack scenario
        $('#attacks tbody').innerHTML = empty
            ? '<tr><td colspan="3" class="text-muted">No password entered.</td></tr>'
            : result.attacks.map(({ name, rate, time }) => `
                <tr>
                    <td>${escapeHtml(name)}</td>
                    <td>${escapeHtml(PasswordAnalyser.formatRate(rate))}</td>
                    <td class="text-right font-weight-bold">${escapeHtml(time)}</td>
                </tr>`).join('');

        // rules checklist
        document.querySelectorAll('#rules li').forEach((li) => {
            const ok = result.rules[li.dataset.rule] === true;
            li.classList.toggle('passed', !empty && ok);
            li.classList.toggle('failed', !empty && !ok);
        });

        // feedback
        $('#feedback').innerHTML = empty
            ? '<li class="text-muted">Start typing to see suggestions.</li>'
            : result.feedback
                .map(({ type, msg }) => `<li class="${type}">${escapeHtml(msg)}</li>`)
                .join('');

        // breakdown table
        $('#breakdown tbody').innerHTML = result.breakdown.length === 0
            ? '<tr><td colspan="4" class="text-muted">No password entered.</td></tr>'
            : result.breakdown.map(({ name, count, points, rule }) => `
                <tr>
                    <td>${escapeHtml(name)}</td>
                    <td><code class="rule-code">${escapeHtml(rule)}</code></td>
                    <td>${count}</td>
                    <td class="text-right ${points >= 0 ? 'pts-plus' : 'pts-minus'}">${points > 0 ? '+' : ''}${points}</td>
                </tr>`).join('');
    };

    // real time feedback on every change (typing, paste, autofill)
    pwd.addEventListener('input', () => render(PasswordAnalyser.analyse(pwd.value)));

    // show / hide password
    toggleBtn.addEventListener('click', () => {
        const show = pwd.type === 'password';
        pwd.type = show ? 'text' : 'password';
        toggleBtn.textContent = show ? 'Hide' : 'Show';
        toggleBtn.setAttribute('aria-pressed', String(show));
        pwd.focus();
    });

    $('#pwdForm').addEventListener('submit', (e) => e.preventDefault());

    render(PasswordAnalyser.analyse(''));
});
