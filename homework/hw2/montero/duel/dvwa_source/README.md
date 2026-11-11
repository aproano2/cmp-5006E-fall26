# Reviewed scan inputs

The three `*_medium.php` files are snapshots of the upstream DVWA exercises:

- `sqli/source/medium.php` → `sqli_medium.php`
- `xss_r/source/medium.php` → `xss_medium.php`
- `exec/source/medium.php` → `exec_medium.php`

Upstream: https://github.com/digininja/DVWA, source checkout
`a1978a2fed195acd093010af6395f86a281537ca`. Copyright and license are
preserved in COPYING.txt. These deliberately vulnerable snippets are not ours.

The runner compares each normalized snapshot against the running DVWA container
before the experiment. The image digest and other environment details are in
../environment.json. The combined review source is hashed in
../reviewed_inputs.json and ../part_c_results.json.

`sqli_fixed.php` is a byte-for-byte text copy of our evaluated
../../defend/medium_parameterized.php and serves as a negative control. The
reference describes the three intended findings; it is not an exhaustive audit
of every possible issue in DVWA or its surrounding authentication code.
