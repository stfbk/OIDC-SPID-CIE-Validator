# OIDC-SPID/CIE-Validator

OIDC-SPID/CIE-Validator offers a streamlined version of [MIG](https://github.com/stfbk/mig/) [1] for Relying Parties (RPs) to perform preliminary verification of compliance with the [SPID/CIE OIDC Specification](https://docs.italia.it/italia/spid/spid-cie-oidc-docs). This includes a total of 252 tests for both the Entity Configuration (EC) response and the Authorization (AR) request. These tests verify the presence, type, expected values, unacceptable values, and the validity of the signature across all mandatory, conditional, and optional parameters, as specified in the SPID/CIE OIDC Specification.

OIDC-SPID/CIE-Validator uses JSON Schemas to validate the JWT in both the EC response and request in the AR. Additionally, OIDC-SPID/CIE-Validator verifies the correctness of parameters in the EC response and AR request through script-based validation.

The required inputs are the Entity Configuration endpoint URL (URL_EC) and the URL for generating the AR request (URL_AR).

OIDC-SPID/CIE-Validator outputs results in two modes:

- In verbose mode, it provides detailed feedback on both passed and failed tests, including explanations or suggested mitigations for failures.
- In non-verbose mode, it only reports failed tests, along with the reasons and potential solutions.

## Summary

- [OIDC-SPID/CIE-Validator](#oidc-spidcie-validator)
  - [Summary](#summary)
  - [What is in this Repo](#what-is-in-this-repo)
    - [Swagger](#swagger)
    - [Schemas](#schemas)
    - [Tool](#tool)
  - [Requirements](#requirements)
  - [Quickstart](#quickstart)
    - [Linux, MacOS or WSL](#linux-macos-or-wsl)
      - [Automatic](#automatic)
      - [Manual](#manual)
    - [For Windows](#for-windows)
  - [Using OIDC-SPID/CIE-Validator](#using-oidc-spidcie-validator)
  - [References](#references)
  - [License](#license)

![example](doc/img/mig_rpvalidation.gif)

## What is in this Repo

```bash
OIDC-SPID/CIE-Validator
├── run.sh
├── swagger
│   ├── openapi_cie.yaml
│   ├── openapi_spid.yaml
├── schemas
│   ├── ARR_body.json
│   ├── ARR_body_SPID.json
│   ├── ARR_header.json
│   ├── EC_body.json
│   ├── EC_body_SPID.json
│   ├── EC_header.json
│   ├── TM_body.json
│   └── TM_header.json
└── tool
    ├── mig_validator.py
    └── style_table.py
```

### Swagger

The tool supports the OpenAPI Specification (Swagger) to simplify API validation and ensure SPID/CIE OIDC compliance. Key features include:

1. **Define OIDC-SPID/CIE in a Standardized Format**: The tool uses the OpenAPI Specification (OAS) v3.1.0 for API documentation and validation.
2. **Custom Extensions**: Handles SPID/CIE-specific rules using x-comparison-parameter, x-signature, and similar fields for advanced validation.
3. **Provided API Spec**: The repository includes Swagger YAML files in [swagger](#swagger) directory for both CIE and SPID.

### Schemas

The schemas folder contains the JSON Schemas used to validate various JWT components. Each schema is named according to the specific JWT it validates:

1. **Entity Configuration** (EC),
2. **JWT Request of the Authentication Request** (ARR),
3. **Trust Mark** (TM) inside the EC.

The schemas are further divided into two sections: **header** and **body**, ensuring validation for both parts of the JWT.

### Tool

The tool folder provides:

1. **mig_validator**, a script that perform the comparison
2. **style_table**, a script used to style the output

## Requirements

- **Python**: 3.10 or higher

## Quickstart

OIDC-SPID/CIE-Validator is based on python and can be executed via the following methods:

### Linux, MacOS or WSL

<details>
<summary>Details</summary>

#### Automatic

<details>
<summary>Details</summary>

Run the bash script: `sh validator.sh`

This will create a virtual environment, activates it and installs dependencies, and starts the tool.

</details>

#### Manual

<details>
<summary>Details</summary>

1. Create a virtual environment: `python3 -m venv .venv`
2. Activate the virtual environment: `source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the tool: `python3 tool/mig_validator.py`

</details>

</details>

### For Windows

<details>
<summary>Details</summary>

1. Create a virtual environment: `python3 -m venv .venv`
2. Activate the virtual environment. Activating the environment differs between shells:
   1. In CMD: `.venv\Scripts\activate.bat`
   2. In PowerShell: `.venv\Scripts\Activate.ps1`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the tool: `python3 tool/mig_validator.py`

</details>

## Using OIDC-SPID/CIE-Validator

OIDC-SPID/CIE-Validator will require two inputs:

1. **EID**: the entity id to add .well-known/openid-federation
2. **URL_AR**: the URL to generate the Authorization Request. It can be a direct link or the one generated by the javascript button

These inputs can be provided via command-line arguments (using `--eid <URL_EC>` or `--ar <URL_AR>`) or through interactive prompts.

There are also optional arguments:

- `--v`, to receive a **verbose** output
- `--f <filename>` or `--filename <filename>`,  if you want to add a file as input, e.g., to run the tool on multiple RPs. It contains the list of URLs, where URL_EC is in the first line and URL_AR in the second. See the [sample file](sample_inputfile.txt). To improve readability, blank lines between URLs are allowed. These blank lines will be ignored during processing.
- `--spid`, to execute SPID compliance instead of the CIE on default

Example command: `sh run.sh --eid "https://testing_rp.fbk/" --ar "https://testing_rp.fbk/request"`

## References

1. [Micro-Id-Gym - Identity Management Workouts with Container-Based Microservices](https://st.fbk.eu/tools/Micro-Id-Gym.html)

## License

Everything in this repository is licensed under the [Apache 2.0 license](LICENSE)

```text
Copyright 2024, Fondazione Bruno Kessler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Designed and developed within [Security & Trust](https://st.fbk.eu/) Research Unit at [Fondazione Bruno Kessler](https://www.fbk.eu/en/) (Italy) in cooperation with [Istituto Poligrafico e Zecca dello Stato](https://www.ipzs.it/) (Italy).
