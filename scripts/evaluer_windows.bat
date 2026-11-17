@echo off
rem Evaluation complete du RAG sous Windows : verifie Python et Ollama, installe les dependances,
rem construit l'index sur l'echantillon puis compare RAG hybride, RAG FAISS et LLM seul.
rem Double-cliquer sur ce fichier. Resultats : data\eval\results\rapport_evaluation.md
setlocal EnableExtensions
title Evaluation du RAG cyber
cd /d "%~dp0.."

rem Environnement Python hors du dossier du depot : chemin sans accent, rien a versionner.
set "VENV=%USERPROFILE%\.venvs\rag-cyber-mitre-nvd"
set "VPY=%VENV%\Scripts\python.exe"
set "PYTHONUTF8=1"
set "PYTHONUNBUFFERED=1"
set "HF_HUB_DISABLE_SYMLINKS_WARNING=1"
set "RAG_TIMEOUT=600"

echo.
echo ================================================================
echo  Evaluation du RAG : RAG hybride, RAG FAISS et Mistral seul
echo ================================================================
echo.

rem --- Python 3.11 ou plus recent ---
set "PY="
for %%V in (3.13 3.12 3.11) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
  )
)
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo [ERREUR] Python 3.11, 3.12 ou 3.13 est introuvable.
  echo Installez-le depuis https://www.python.org/downloads/ en cochant "Add python.exe to PATH",
  echo puis relancez ce fichier.
  goto :fin
)
echo Python : %PY%

rem --- Ollama ---
set "OLLAMA=ollama"
where ollama >nul 2>&1
if errorlevel 1 set "OLLAMA=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
if not "%OLLAMA%"=="ollama" if not exist "%OLLAMA%" (
  echo [ERREUR] Ollama n'est pas installe.
  echo Telechargez-le sur https://ollama.com/download , installez-le, puis relancez ce fichier.
  goto :fin
)
"%OLLAMA%" list >nul 2>&1
if errorlevel 1 (
  echo Demarrage du serveur Ollama...
  start "Ollama" /min "%OLLAMA%" serve
  timeout /t 10 /nobreak >nul
)
echo.
echo --- Modele Mistral : environ 4 Go a telecharger au premier lancement ---
"%OLLAMA%" pull mistral
if errorlevel 1 (
  echo [ERREUR] Le telechargement du modele a echoue : verifiez la connexion et qu'Ollama est lance.
  goto :fin
)

rem --- Environnement Python ---
if not exist "%VPY%" (
  echo.
  echo --- Creation de l'environnement Python ---
  %PY% -m venv "%VENV%"
  if errorlevel 1 goto :erreur
)
echo.
echo --- Installation des dependances : quelques minutes au premier lancement ---
"%VPY%" -m pip install --quiet --upgrade pip
"%VPY%" -m pip install -r requirements.txt
if errorlevel 1 goto :erreur

rem --- Pipeline ---
echo.
echo --- 1/3 Preparation de l'echantillon : 50 techniques, 50 CVE ---
"%VPY%" -m rag_cyber prepare --sample
if errorlevel 1 goto :erreur
echo.
echo --- 2/3 Index FAISS : telecharge le modele d'embeddings au premier lancement ---
"%VPY%" -m rag_cyber index
if errorlevel 1 goto :erreur
echo.
echo --- 3/3 Evaluation : 60 reponses de Mistral, de 10 a 60 minutes selon la machine ---
"%VPY%" -m rag_cyber evaluate
if errorlevel 1 goto :erreur

echo.
echo Termine. Rapport : data\eval\results\rapport_evaluation.md
echo Pour discuter avec l'assistant : "%VPY%" -m streamlit run app.py
goto :fin

:erreur
echo.
echo [ERREUR] Une etape a echoue : le message au-dessus indique laquelle.

:fin
echo.
pause
