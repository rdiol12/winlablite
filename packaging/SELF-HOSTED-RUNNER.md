# Run CI on your own Windows PC (self-hosted runner)

GitHub's own runners cost Actions minutes on a private repository. A
self-hosted runner is free: the jobs run on your PC instead, and the repo
stays private. Keep it private: on a public repository anyone could send a
pull request that runs code on your PC.

## 1. Install the tools once

- **Git for Windows** (git-scm.com), with the default options. The workflows
  put its Unix tools (`sh`, `tar`) on the PATH for the job themselves.
- **Python 3.12** (python.org). Tick "Add python.exe to PATH". Check in a new
  window: `python --version` says 3.12.
- **Inno Setup 6** (jrsoftware.org/isdl.php), for the installer build.
- **Build Tools for Visual Studio 2022** (visualstudio.microsoft.com/visual-cpp-build-tools),
  workload **Desktop development with C++**. The exe build compiles winlab's
  licence and pack modules with Cython, which needs this C++ compiler.
- Only for releases: **PowerShell 7** (`winget install Microsoft.PowerShell`)
  and **GitHub CLI** (`winget install GitHub.cli`).

## 2. Add the runner

1. On GitHub open **rdiol12/winlab > Settings > Actions > Runners > New
   self-hosted runner**, and pick **Windows**, x64.
2. Open PowerShell (not as administrator) and paste the page's
   **Download** commands one by one. Use a short folder such as
   `C:\actions-runner`.
3. Paste the **Configure** command (`./config.cmd --url ... --token ...`).
   Press Enter at every question to keep the defaults. When it asks to run
   as a service, answer **N**.
4. Start it: `./run.cmd`. It says "Listening for Jobs". Leave the window open
   while you want CI to run; close it to stop.

## 3. Send the jobs to your PC

On GitHub open **Settings > Secrets and variables > Actions > Variables**,
and add a repository variable `WINLAB_RUNNER` with the value `self-hosted`.

From then on the ci and release workflows run on your PC. Delete the
variable to go back to GitHub's runners.

## What changes on your PC

- The Linux test runs are skipped (your PC is Windows). The Windows test
  run, the PowerShell checks, the exe build and the installer test all run.
- The console-host smoke test is skipped: it adds a local account and a
  SYSTEM scheduled task, which belongs on a throwaway machine only.
- The installer test installs winlab per user into the runner's temp folder
  and uninstalls it again. PSScriptAnalyzer is installed for your user.
- Jobs queue one after another, so a full run takes longer than on GitHub.
