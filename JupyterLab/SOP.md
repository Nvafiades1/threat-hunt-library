<!-- ========================================================= -->
# Standard Operating Procedure
## Title  : JupyterLab — Installation & Daily Use on Windows
## Version: 1.1            Date: 2025-05-28
<!-- ========================================================= -->

### 1 Purpose  
Provide a repeatable process for installing **Python** with **pyenv-win**, building an isolated **virtual environment (venv)**, installing **JupyterLab**, and launching / shutting it down—**with clear explanations of *why* each step is needed.**



### 2 Scope  
All engineers running JupyterLab on corporate Windows 10/11 workstations.



### 3 Prerequisites & Rationale
| Requirement | Why it matters |
|-------------|----------------|
| Local-admin rights | Needed to edit `PATH`, install pyenv-win, and create scripts in `C:\Apps`. |
| Internet access or internal PyPI mirror | Required to download Python builds and pip packages. |
| `C:\Apps` folder | Single, predictable location for tooling that won’t collide with corporate software. |
| `jupyterlab-requirements.txt` | Ensures everyone installs the identical, security-approved package list. |



### 4 Procedure (with explanations)

#### 4.1 Install Python with *pyenv-win*

| Step | Command | Explanation |
|------|---------|-------------|
| 1 | **Open Command Prompt** | All subsequent commands run here; CMD is used because pyenv-win’s shims auto-load into CMD more predictably than PowerShell. |
| 2 | `pyenv --version` | Confirms pyenv-win is installed and on `PATH`. If it isn’t, nothing else will work. |
| 3 | `pyenv install standard` | Downloads & compiles the “standard” build (an alias in pyenv-win pointing to the latest stable CPython). Keeps corporate Python separate from the one bundled with Windows or other apps. |
| 4 | `pyenv global standard` <br> `pyenv local standard` | **Global** makes “standard” the default everywhere; **local** pins the current directory to the same version—handy if you clone repos with `.python-version` files. |
| 5 | `python --version` / `pip --version` | Verifies the shims point to the new interpreter. |
| 6 | `python -m pip install --upgrade pip` <br> `pip install --upgrade setuptools wheel` | Ensures the *packaging* stack is current, which avoids TLS/cert issues and wheel-build headaches later. |



#### 4.2 Create a Virtual Environment

| Step | Command | Explanation |
|------|---------|-------------|
| 1 | `cd C:\Apps` / `mkdir py-venvs` | Keeps all venvs in one location so disk clean-ups or reinstalls don’t hit system folders. |
| 2 | `python -m venv jupyterlab` | Builds a **self-contained** Python runtime where packages won’t pollute (or be polluted by) the global site-packages dir. |
| 3 | **Activate venv** <br> • CMD → `.\\jupyterlab\\Scripts\\activate` <br> • PS  → `...\\Activate.ps1` | Temporarily rewires `PATH` so `python` and `pip` point to the venv copy. You *must* activate before installing packages or running Jupyter. |
| 4 | `python -m pip install --upgrade pip` <br> `pip install --upgrade setuptools` | Even inside the venv, bump pip & setuptools—the venv starts with whatever version the global site-packages had. |



#### 4.3 Install JupyterLab & Packages

| Step | Command | Explanation |
|------|---------|-------------|
| 1 | Copy `jupyterlab-requirements.txt` | Central control: security reviews one file; everyone installs the same bits. |
| 2 | `pip install --no-cache-dir -r jupyterlab-requirements.txt` | Installs exact package set. `--no-cache-dir` guarantees fresh pulls (avoids stale or compromised wheels). |
| 3 | `deactivate` | Closes the venv context so the shell is “clean” for whatever comes next. |



#### 4.4 Daily Launch of JupyterLab

| Step | Command | Explanation |
|------|---------|-------------|
| 1 | **Open new CMD** | Fresh shell means fresh environment; avoids inheriting stale variables. |
| 2 | `cd <project-folder>` | JupyterLab’s file browser roots itself here, so pick the directory where your notebooks live. |
| 3 | Re-activate venv | You’re back inside the isolated Python context (see 4.2-3). |
| 4 | `jupyter lab --ip 0.0.0.0 --allow-root` | Starts JupyterLab. `--ip 0.0.0.0` listens on all interfaces (important for WSL or remote-access); `--allow-root` prevents startup failure if Windows claims UID 0 due to antivirus sandboxing. |
| 5 | If browser error → replace `<hostname>:8888` with `localhost:8888` | Some corporate DNS rewrite proxies break loopback hostnames. Manually swapping to localhost sidesteps this. |



#### 4.5 Shutdown & Cleanup

| Step | Command | Explanation |
|------|---------|-------------|
| 1 | **File → Shutdown** in JupyterLab | Graceful stop ensures kernels finish writing checkpoints; avoids orphaned Python processes. |
| 2 | `deactivate` | Returns shell to normal PATH—prevents accidental package installs outside the venv at your next command prompt. |


### 5 Quick-Reference Commands

| Action | Command |
|--------|---------|
| Activate venv (CMD) | `C:\Apps\py-venvs\jupyterlab\Scripts\activate` |
| Activate venv (PS)  | `C:\Apps\py-venvs\jupyterlab\Scripts\Activate.ps1` |
| Start JupyterLab    | `jupyter lab --ip 0.0.0.0 --allow-root` |
| Fallback URL        | Switch `<hostname>:8888` → `localhost:8888` |
| Shutdown JupyterLab | **File → Shutdown** |
| Deactivate venv     | `deactivate` |



### 6 Troubleshooting & Why It Happens

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| `pyenv` not recognised | PATH not updated | Reopen CMD or add `%USERPROFILE%\.pyenv\pyenv-win\bin` to PATH. |
| Browser 404 at launch | Proxy rewrote hostname | Replace with `localhost:8888`. |
| Pip install fails behind proxy | TLS interception strips cert chain | Export `REQUESTS_CA_BUNDLE` pointing at corporate root CA or use internal mirror. |
| PowerShell refuses `Activate.ps1` | Execution policy default is *Restricted* | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |



### 7 Revision History

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2025-05-28 | TDE Team | Initial release |
| 1.1 | 2025-05-28 | TDE Team | Added detailed explanations per request |

<!-- ========================= END OF SOP ========================= -->
