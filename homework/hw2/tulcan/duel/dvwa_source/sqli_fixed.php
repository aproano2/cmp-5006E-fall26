<?php
// HW2 group fix for DVWA's MySQL numeric-ID sink, deployed at Medium.
// Input is bound as one value; it never becomes part of the SQL statement.
if ($_DVWA['SQLI_DB'] !== MYSQL) {
    throw new RuntimeException('This evaluated patch requires the MySQL backend.');
}
$connection = $GLOBALS['___mysqli_ston'];
$html .= '<!-- HW2 parameterized fix -->';
if (isset($_POST['Submit'])) {
    $id = (string) ($_POST['id'] ?? '');
    $statement = mysqli_prepare($connection,
        'SELECT first_name, last_name FROM users WHERE user_id = ?');
    if (!$statement) {
        throw new RuntimeException('Could not prepare the fixed query.');
    }
    mysqli_stmt_bind_param($statement, 's', $id);
    if (!mysqli_stmt_execute($statement)) {
        throw new RuntimeException('Could not execute the fixed query.');
    }
    $result = mysqli_stmt_get_result($statement);
    while ($row = mysqli_fetch_assoc($result)) {
        // Also encode values at the HTML boundary: the ID may contain markup.
        $display_id = htmlspecialchars($id, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $first = htmlspecialchars($row['first_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $last = htmlspecialchars($row['last_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html .= "<pre>ID: {$display_id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }
    mysqli_stmt_close($statement);
}
$result = mysqli_query($connection, 'SELECT COUNT(*) FROM users');
if (!$result) {
    throw new RuntimeException('Could not count users.');
}
$number_of_rows = mysqli_fetch_row($result)[0];
mysqli_close($connection);
?>
