# Common Desktop Application Import Formats — Attack Surface

## Project / Solution Files

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.sln` | Visual Studio, Rider | MSBuild pre/post-build events, inline tasks |
| `.csproj` / `.vbproj` | .NET IDEs | MSBuild `<Exec>`, UsingTask code execution |
| `.vcxproj` | Visual Studio C++ | Custom build steps, pre/post-build events |
| `.proj` / `.targets` | MSBuild | Arbitrary MSBuild task execution |
| `.gradle` | Android Studio, IntelliJ | Groovy code execution |
| `.pbxproj` | Xcode | Build phase scripts |

## Archive / Package Files

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.zip` | Nearly all | Zip Slip (path traversal), symlink attacks |
| `.tar` / `.tar.gz` | Dev tools | Path traversal, symlink following |
| `.nupkg` | NuGet / .NET | Install scripts, dependency confusion |
| `.vsix` | Visual Studio | Extension code execution |
| `.jar` | Java apps | Deserialization, code execution |

## CAD / Engineering

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.dwg` / `.dxf` | AutoCAD, viewers | Paired with acaddoc.lsp auto-execute |
| `.dcl` | AutoCAD | Dialog + AutoLISP code execution |
| `.lsp` / `.fas` / `.vlx` | AutoCAD | Direct AutoLISP execution |
| `.scr` | AutoCAD | Script command execution |
| `.rvt` | Revit | Dynamo script execution |
| `.3dm` | Rhino | Python/GhPython scripts |

## Document Formats (XML-based)

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.docx` / `.xlsx` / `.pptx` | Office apps | XXE in XML parts, macro remnants |
| `.odt` / `.ods` | LibreOffice | Macro execution, XXE |
| `.svg` | Image viewers, browsers | XXE, XSS (in web context) |
| `.xsl` / `.xslt` | XML processors | XSLT code execution |

## Database / Data Files

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.mdb` / `.accdb` | MS Access apps | Macro/VBA auto-execute |
| `.sqlite` / `.db` | Various | SQL injection if queries are dynamic |
| `.csv` | Spreadsheet apps | Formula injection (DDE) |
| `.json` | Various | .NET deserialization with TypeNameHandling |
| `.xml` | Various | XXE, XSLT injection |
| `.yaml` | Various | YAML deserialization (SnakeYAML, PyYAML) |

## Help / Documentation

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.chm` | Windows Help | ActiveX command execution |
| `.hlp` | Legacy Windows | WinHelp macro execution |
| `.pdf` | PDF viewers | JavaScript execution, launch actions |

## Plugin / Extension Files

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.dll` | Most Windows apps | DLL hijack, sideloading |
| `.so` | Linux apps | Shared library hijack |
| `.dylib` | macOS apps | DYLIB hijacking |
| `.xll` | Excel | Excel add-in code execution |
| `.wll` | Word | Word add-in code execution |
| `.vsto` | Office | .NET Office add-in |

## Configuration Files

| Format | Apps | Attack Vector |
|--------|------|---------------|
| `.config` | .NET apps | XXE, deserialization settings |
| `.ini` | Various | Path injection, credential theft |
| `.reg` | Windows | Registry modification |
| `.properties` | Java apps | JNDI injection values |
