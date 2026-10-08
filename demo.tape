Output demo.gif

Set FontSize 16
Set Width 1400
Set Height 850
Set Theme "Dracula"
Set TypingSpeed 40ms
Set Padding 20

Type "iam-paths scan --file samples/sample_account.json"
Enter
Sleep 5s

Type `iam-paths scan --file samples/sample_account.json --format json --fail-on critical > /dev/null; echo "exit code: $?"`
Enter
Sleep 4s
