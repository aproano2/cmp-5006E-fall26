# Where our attack, defense, or comparison might be unfair

Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez

Class: Computer Security

Date: 6/11/2026

## 1. Was the ground truth built independently of the tools we scored?

Yes, but we did not build it from scratch. We reused the instructor fixture `ground_truth.json`, read `vulnweb_app.py` line by line ourselves and agree with all its entries (three real findings, one true negative, one class not present). It was fixed before sqlmap or the LLM ran and we did not change it after seeing their output, so it is not tuned to either tool.

Two weaknesses remain. With only three real findings, each one moves recall by 0.33, so the scores are very coarse. And it lists only the three intended bugs. Some things a reviewer could reasonably call real are not in it, for example `do_login` returns the raw SQL error together with the full query to the client. Neither tool reported those, so the numbers did not change, but a tool that did would have been counted as a false positive.

## 2. Did we tune one side more than the other?

Yes, in both parts.

In Part C, sqlmap ran with level 3 and risk 3. We raised them after our first try with the default settings found nothing, because sqlmap itself suggests raising them (`duel/raw/sqlmap_first_try_default_settings.log`). The LLM got one plain prompt that we wrote once and never improved, and a small model (qwen2.5:1.5b, the only one we had pulled, while the course default is qwen2.5:3b). So sqlmap got one round of tuning and the LLM got none. We also removed the comments from the source before giving it to the LLM, which makes its job harder, and our parser skips the lines where the model says "None", which helps it.

In Part B, the WAF was written knowing the Part A payload and the attack battery it was then measured on, so 6 of 6 coverage says very little about real coverage. The three bypasses were found by the same people who wrote the rules, with the rules in front of them.

## 3. Is the benign corpus realistic, or does it dodge our rules by luck?

It is not a sample of real traffic. We used the instructor `benign_traffic.json` (26 entries), which was written on purpose with attack looking English ("drop table tennis", "select the union option"). The login part has only 9 usernames, so one entry moves the login false positive rate by 11 points, and the 22.2 % figure has a very wide margin.

It also misses the field that matters most. The three B1 bypasses go in the password field, and the WAF inspects the password too, but the corpus has no passwords. The comment rule blocks any `#` and the stacked query rule blocks any semicolon, so a real password like `Tr0ub4dor#3`, or any password with a semicolon in it, would be rejected. So the false positive cost on real logins is probably underestimated. The whole corpus rate (3 of 26, 11.5 %) also runs the login WAF over search and name fields that it does not protect, so that number is hypothetical.

## 4. Which Part A finding are we least sure reproduces, and why?

The command injection. `do_ping` does not run any command. It computes `injection_detected` itself with a regex over the host string, and our oracle only checks that this flag says true. So we confirmed that a shell metacharacter reached the command string, not that `whoami` ran. The oracle is also a plain string match on `"injection_detected": true`, so it depends on the exact spacing `json.dumps` uses.

The SQL injection is confirmed by the admin canary coming back, and the XSS by the `<script>` tag appearing unescaped, so we trust those two more. One more limit applies to all three: the assignment asks for a bypass of a Medium filter, and the target app has no filter, so none of our Part A payloads needed a bypass.
