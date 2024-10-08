[![Logo](https://resources.mend.io/mend-sig/logo/mend-dark-logo-horizontal.png)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)

# Mend SBOM Cli

Generation SBOM reports in the SPDX or CycloneDx formats  

<hr>

- [Supported Operating Systems](#supported-operating-systems)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration Parameters](#configuration-parameters)
- [Execution Examples](#execution-examples)

<hr>

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
- Python 3.9+
- Mend user with at least Product Admin permissions

## Installation
```
$ pip install mend-sbom-export-cli
```
> **Note:** Depending on whether the package was installed as a root user or not, you need to make sure the package installation location was added to the `$PATH` environment variable.

## Configuration Parameters
>**Note:** Parameters can be specified as either command-line arguments, environment variables, or a combination of both.  
> 
> Command-line arguments take precedence over environment variables.  

| CLI argument                    | Env. Variable     |   Type   | Required | Description                                                                                                    |
|:--------------------------------|:------------------|:--------:|:--------:|:---------------------------------------------------------------------------------------------------------------|
| **&#x2011;&#x2011;help**        |                   | `switch` |    No    | Show help and exit                                                                                             |
| **&#x2011;&#x2011;api-key**     | `WS_APIKEY`       | `string` |   No*    | Mend API Key                                                                                                   |
| **&#x2011;&#x2011;service**     | `WS_SERVICEUSER`  | `string` |   No*    | Mend Service User email                                                                                        |
| **&#x2011;&#x2011;user-key**    | `WS_USERKEY`      | `string` |   Yes    | Mend User Key (your own personal user key if Mend API Key provided or user key of service user)                |
| **&#x2011;&#x2011;url**         | `WS_WSS_URL`      | `string` |   Yes    | Mend Server URL                                                                                                |
| **&#x2011;&#x2011;product**     | `WS_PRODUCTTOKEN` |  `string`  |   No    | Empty String <br />(Include all products). Comma-separated list of Mend Product Tokens that should be included |
| **&#x2011;&#x2011;project**     | `WS_PROJECTTOKEN` |  `string`  |   No    | Empty String <br />(Include all projects). Comma-separated list of Mend Project Tokens that should be included |
| **&#x2011;&#x2011;exclude**     | `WS_EXCLUDETOKEN` |  `string`  |    No    | Empty String <br /> (No exclusions).Commsa-separated list of Mend Project Tokens that should be excluded       |
| **&#x2011;&#x2011;licensetext** |                   | `bool`   |    No    | Include full license text for all libraries (default: `False`)                                                 |
| **&#x2011;&#x2011;dir**         |                   | `string` |    No    | Output directory for the report files (default: `current folder`)                                                |
| **&#x2011;&#x2011;type**        |                   | `string` |    No    | Report format [`spdx` `cdx`] (default: `spdx`)                                                                 | 
| **&#x2011;&#x2011;threads**     |                   |  `int`   |    No    | Number of threads to run in parallel for report generation (default: `10`)                                     |

`*` One of the parameters must be specified (Api-key or Mend Service User email).  
The Service User or your user should have the rights to work with the requested org/product/projects.

## Execution Examples

**Using command-line arguments only:**
```shell
sbom_export_cli --user-key WS_USERKEY --api-key WS_APIKEY --url $WS_WSS_URL --product `ProductToken1`,`ProductToken2` --project `ProjectToken` --dir $OUTPUT_DIRECTORY
```
**Using environment variables:**
```shell
export WS_USERKEY=xxxxxxxxxxx
export WS_APIKEY=xxxxxxxxxxx
export WS_WSS_URL=https://saas.mend.io

sbom_export_cli --product `ProductToken`
```
> **Note:** Either form is accepted. For the rest of the examples, the latter form would be used  
> **Note:** In the following examples, $WS_USERKEY, $WS_APIKEY and $WS_WSS_URL are assumed to have been exported as environment variables.  

Create CycloneDx SBOM reports

```shell
$ sbom_export_cli --project "$WS_PROJECTTOKEN" --dir $HOME/reports --type cdx
```

Create SPDX reports

```shell
$ sbom_export_cli --product "$WS_PRODUCTTOKEN" --dir $HOME/reports --licensetext True 
```
