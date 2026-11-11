<?php
// Negative model deployed before the original Medium SQL sink.
$html .= '<!-- HW2 deployed WAF -->';
if (isset($_POST['Submit'])) {
    $value = html_entity_decode(urldecode((string) ($_POST['id'] ?? '')), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $rules = [
        '~\b(?:or|and)\b\s+\d+\s*=\s*\d+~i',
        '~union[\s/*]+select~i',
        '~<\s*script\b~i',
        '~\bdrop[\s/*]+table~i',
        '~[;&|`$()]~',
    ];
    foreach ($rules as $rule) {
        if (preg_match($rule, $value)) {
            echo '<pre>HW2 WAF blocked</pre>';
            exit;
        }
    }
}
require '/tmp/hw2-original-medium.php';
?>
