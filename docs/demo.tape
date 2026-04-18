# Pentest Swarm AI — README demo GIF
# Generate with: vhs docs/demo.tape
#
# Notes:
#   - Uses the already-built binary at ./bin/pentestswarm
#   - Does NOT run a real scan (requires an API key) — showcases help,
#     system health (doctor), and the scan command surface
#   - Keep this reproducible: any CLI change that breaks this tape
#     should trigger a regeneration

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set WindowBar Colorful
Set Margin 16
Set MarginFill "#1a1a2e"
Set BorderRadius 8
Set LetterSpacing 0.5
Set LineHeight 1.2

# ---- Scene 1: clean terminal, set the stage ----
Hide
Type `export PATH="$(pwd)/bin:$PATH"`
Enter
Type "clear"
Enter
Show

Sleep 500ms

# ---- Scene 2: show the CLI surface ----
Type "pentestswarm --help"
Sleep 400ms
Enter
Sleep 3500ms

Type "clear"
Enter
Sleep 300ms

# ---- Scene 3: system health check (the pretty one) ----
Type "pentestswarm doctor"
Sleep 400ms
Enter
Sleep 3500ms

Type "clear"
Enter
Sleep 300ms

# ---- Scene 4: the scan command surface ----
Type "pentestswarm scan --help"
Sleep 400ms
Enter
Sleep 3500ms

Type "clear"
Enter
Sleep 300ms

# ---- Scene 5: the one command users care about ----
Type "# Launch the swarm against a target:"
Enter
Sleep 600ms
Type "pentestswarm scan example.com --scope example.com --mode bugbounty --follow"
Sleep 2500ms
