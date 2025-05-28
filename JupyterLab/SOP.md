# Standard Operating Procedure
## Title  : JupyterLab — Installation & Daily Use on Windows
## Date: 2025-05-28


### 1  Purpose  
Provide a repeatable process for installing **Python** with **pyenv-win**, creating an isolated **virtual environment**, installing **JupyterLab**, connecting to **Azure Data Explorer (ADX)**, and safely launching / shutting down JupyterLab—**with explanations of *why* each step matters.**

### 2  Scope  
All engineers who use JupyterLab on corporate Windows 10/11 workstations.


### 3  Prerequisites
| Requirement | Why it matters |
|-------------|----------------|
| Local-admin rights | Needed to edit `PATH`, install pyenv-win, and create scripts. |
| Internet access / internal PyPI mirror | Required to download Python builds and pip packages. |
| Folder `C:\Apps` | Keeps tooling in a predictable, non-system location. |
| `jupyterlab-requirements.txt` | Security-approved, version-pinned package list. |


### 4  Procedure  (with explanations)

#### 4.1  Install Python with *pyenv-win*
| Step | Command | Explanation |
|------|---------|-------------|
| 1 | Open **Command Prompt** | CMD handles pyenv shims reliably. |
| 2 | `pyenv --version` | Confirms pyenv-win is installed and on `PATH`. |
| 3 | `pyenv install standard` | Downloads & installs the latest stable CPython as **standard**. |
| 4 | `pyenv global standard`  `pyenv local standard` | Makes **standard** the default interpreter globally & in current dir. |
| 5 | `python --version`  `pip --version` | Verifies new interpreter and pip are active. |
| 6 | `python -m pip install --upgrade pip`   `pip install --upgrade setuptools wheel` | Updates packaging tool-chain to avoid TLS / build errors. |

#### 4.2  Create a Virtual Environment
| Step | Command | Explanation |
|------|---------|-------------|
| 1 | `cd C:\Apps`  `mkdir py-venvs` | Centralises all venvs for easy cleanup. |
| 2 | `python -m venv jupyterlab` | Creates an isolated Python runtime. |
| 3 | **Activate** venv  (CMD → `.\\jupyterlab\\Scripts\\activate`  PS → `…\\Activate.ps1`) | Switches `PATH` so `python`/`pip` point to the venv copy. |
| 4 | `python -m pip install --upgrade pip`   `pip install --upgrade setuptools` | Ensures latest pip inside the venv. |

#### 4.3  Install JupyterLab & Packages
| Step | Command | Explanation |
|------|---------|-------------|
| 1 | Copy `jupyterlab-requirements.txt` | Guarantees consistent, vetted packages. |
| 2 | `pip install --no-cache-dir -r jupyterlab-requirements.txt` | Installs packages without cached wheels. |
| 3 | `deactivate` | Leaves the venv cleanly. |

#### 4.4  Daily Launch of JupyterLab *(handled by **Activate.ps1**)*
1. **Open PowerShell**, `cd` to your project folder, and run  
`C:\Apps\py-venvs\jupyterlab\Scripts\Activate.ps1`
The script **activates the venv *and* launches JupyterLab**.  
2. If the browser shows an error page, replace `<hostname>:8888` with **`localhost:8888`**.

#### 4.5  Connect to ADX via Python SDK  (**code included**)

> Use this template to establish a secure connection, run a test query, and pull the result into a pandas DataFrame.

```python
# --- ADX connection boilerplate ---------------------------------
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
import pandas as pd

CLUSTER  = "https://<cluster>.kusto.windows.net"
DATABASE = "<database>"
TENANT   = "<tenant-guid>"            # optional if az CLI context matches

# Prefer Azure CLI token; fall back to device code if not signed in
kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(CLUSTER)
kcsb.authority_id = TENANT            # keep for cross-tenant cases
client = KustoClient(kcsb)
# ---------------------------------------------------------------

# --- Sample query ----------------------------------------------
query = """
CrowdStrikeFDR
| where TimeGenerated > ago(1h)
| summarize events = count() by bin(TimeGenerated, 5m)
"""
result = client.execute(DATABASE, query)
df     = result.primary_results[0].to_dataframe()
print(df.head())
# ---------------------------------------------------------------
```
### 4.6 Using Kqlmagic inside Notebooks (Quick Reference)

| Phase | Action | Why |
|-------|--------|-----|
| Load extension | `%reload_ext Kqlmagic` | Enables Kusto magics. |
| Connect | `%kql AzureDataExplorer://code;cluster='<cluster>';database='<db>';tenant='<tenant>'` | One semicolon-delimited string. |
| Query | `%%kql` cell with multi-line query | Instant table / chart rendering. |
| Export | `df = _kql_raw_result_.to_dataframe()` | Pull result into pandas. |


### 5 Quick-Reference Commands

| Task | Command |
|------|---------|
| Activate venv (CMD) | `C:\Apps\py-venvs\jupyterlab\Scripts\activate` |
| Activate venv **and** launch JupyterLab (PS) | `C:\Apps\py-venvs\jupyterlab\Scripts\Activate.ps1` |
| Change URL if launch fails | Replace `<hostname>:8888` with `localhost:8888` |
| Shutdown JupyterLab | **File → Shutdown** |
| Deactivate venv | `deactivate` |


### 6 Troubleshooting

| Symptom | Root Cause | Resolution |
|---------|------------|-----------|
| `pyenv` not recognised | PATH missing pyenv shims | Reopen CMD or add `%USERPROFILE%\.pyenv\pyenv-win\bin` to PATH. |
| Browser 404 at launch | Proxy rewrote hostname | Use `localhost:8888` in URL. |
| `%kql Unknown option 'cluster'` | Flags split incorrectly | Use a single semicolon-delimited string. |
| Pip install fails behind proxy | TLS interception | Set `REQUESTS_CA_BUNDLE` or use internal mirror. |
| PS activation blocked | Execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
