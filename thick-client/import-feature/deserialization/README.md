# .NET Deserialization Payloads

Exploit insecure deserialization in .NET desktop applications.

**Severity**: CRITICAL  
**Tool**: [ysoserial.net](https://github.com/pwntester/ysoserial.net)

## Files

| File | Description |
|------|-------------|
| [`dotnet_deser.py`](dotnet_deser.py) | Generates ysoserial.net commands for all formatter/gadget combos, Json.Net payload, and detection tips |
| [`java_deser.py`](java_deser.py) | Java deserialization — 16 ysoserial gadget chains (CommonsCollections, Spring, Groovy, Hibernate, etc.), stream detection, library fingerprinting |

## Usage

```bash
python -I dotnet_deser.py --cmd calc.exe --formatter all --output payloads/
```

Outputs:
- `ysoserial_commands.txt` — Ready-to-run ysoserial.net commands
- `jsonnet_payload.json` — Json.Net `$type` payload (for `TypeNameHandling != None`)
- `detection_tips.txt` — How to find deserialization sinks in decompiled code

## How to Identify

Decompile with dnSpy/ILSpy, search for:
- `BinaryFormatter.Deserialize()`
- `SoapFormatter.Deserialize()`
- `NetDataContractSerializer.ReadObject()`
- `JsonConvert.DeserializeObject()` with `TypeNameHandling`
- `JavaScriptSerializer` with `SimpleTypeResolver`

## Which Formatter to Target

| If you see... | Use ysoserial.net formatter |
|--------------|---------------------------|
| Binary blob files (.bin, .dat) | `BinaryFormatter` |
| XML with type annotations | `NetDataContractSerializer` |
| JSON with `"$type"` | `Json.Net` |
| Base64 in configs | `LosFormatter` |
| SOAP messages | `SoapFormatter` |
