/*
 * app.js
 * Hooks the analyser up to the page and updates the UI in real time.
 */

$(document).ready(function () {

    var $pwd = $('#password');

    function escapeHtml(s) {
        return $('<div/>').text(s).html();
    }

    function render(result) {
        // meter
        var $meter = $('#meter');
        $meter.removeClass('progress-bar-danger progress-bar-warning progress-bar-info progress-bar-success')
              .addClass('progress-bar-' + result.label.css)
              .css('width', result.score + '%');

        // stats
        $('#scoreVal').text(result.score);
        $('#strengthVal').text(result.label.text)
            .attr('class', 'stat-value text-' + result.label.css);
        $('#crackVal').text(result.crack);

        // rules checklist
        $('#rules li').each(function () {
            var rule = $(this).data('rule');
            var ok = result.rules[rule] === true;
            var empty = result.length === 0;

            $(this).removeClass('passed failed');
            if (!empty) { $(this).addClass(ok ? 'passed' : 'failed'); }

            $(this).find('.glyphicon')
                .toggleClass('glyphicon-ok', ok)
                .toggleClass('glyphicon-remove', !ok);
        });

        // feedback
        var $fb = $('#feedback').empty();
        if (result.length === 0) {
            $fb.append('<li class="text-muted">Start typing to see suggestions.</li>');
        } else {
            $.each(result.feedback, function (i, item) {
                $fb.append('<li class="' + item.type + '">' + escapeHtml(item.msg) + '</li>');
            });
        }

        // breakdown table
        var $body = $('#breakdown tbody').empty();
        if (result.breakdown.length === 0) {
            $body.append('<tr><td colspan="3" class="text-muted">No password entered.</td></tr>');
        } else {
            $.each(result.breakdown, function (i, row) {
                var cls = row.points >= 0 ? 'pts-plus' : 'pts-minus';
                var sign = row.points > 0 ? '+' : '';
                $body.append(
                    '<tr><td>' + row.name + '</td>' +
                    '<td>' + row.count + '</td>' +
                    '<td class="text-right ' + cls + '">' + sign + row.points + '</td></tr>'
                );
            });
        }
    }

    // real time feedback on every key stroke / paste
    $pwd.on('keyup input paste', function () {
        render(PasswordAnalyser.analyse($pwd.val()));
    });

    // show / hide password
    $('#toggleBtn').on('click', function () {
        if ($pwd.attr('type') === 'password') {
            $pwd.attr('type', 'text');
            $(this).text('Hide');
        } else {
            $pwd.attr('type', 'password');
            $(this).text('Show');
        }
        $pwd.focus();
    });

    render(PasswordAnalyser.analyse(''));
});
