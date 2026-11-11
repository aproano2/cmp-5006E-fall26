# Initial unconstrained-format attempt

Two genuine uncached Ollama calls (seeds 11/29) were made. Run 2 returned invalid
JSON, including unescaped quotes/newlines and an unterminated evidence string.
The evaluator rejected the experiment rather than silently losing findings.
Both original responses and the exact prompt are retained here. They are not
included in the final metric table. Two new calls use a JSON shape constraint;
labels and filenames are still unconstrained. This technical retry is disclosed
because it can change findings. No response is selected for a better score.
