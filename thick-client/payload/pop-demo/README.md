# pop.exe — usage

## Modes

```
pop.exe                             MVTC → MessageBox (default text)
pop.exe <PID>                       that PID → MessageBox
pop.exe <name>                      that process → MessageBox
pop.exe <target> "custom msg"       MessageBox with your text
pop.exe <target> --spawn <program>  spawn child instead
pop.exe --list                      show all injectable processes
pop.exe --help                      usage
```

## Examples

```
pop.exe --list                      # see candidates
pop.exe chrome                      # pop MessageBox in chrome
pop.exe explorer "I was here"       # custom text in explorer
pop.exe firefox --spawn mspaint     # spawn mspaint from firefox
```

## Build

```
cl /EHsc /O2 /nologo pop.cpp /link psapi.lib user32.lib advapi32.lib /OUT:pop.exe
```
