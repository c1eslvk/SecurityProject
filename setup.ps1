# setup.ps1 — pierwsze uruchomienie projektu RBAC (Windows / PowerShell)
# Tworzy srodowisko wirtualne, instaluje zaleznosci, przygotowuje baze,
# role oraz konto administratora.

$py = ".\.venv\Scripts\python.exe"

Write-Host "==> Srodowisko wirtualne (.venv)" -ForegroundColor Cyan
if (-not (Test-Path ".venv")) { python -m venv .venv }

Write-Host "==> Instalacja zaleznosci" -ForegroundColor Cyan
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.txt

Write-Host "==> Plik konfiguracyjny .env" -ForegroundColor Cyan
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }

Write-Host "==> Migracje bazy danych" -ForegroundColor Cyan
& $py manage.py migrate

Write-Host "==> Tworzenie rol (User / Manager / Admin)" -ForegroundColor Cyan
& $py manage.py seed_rbac

Write-Host "==> Konto administratora" -ForegroundColor Cyan
& $py manage.py bootstrap_admin --username admin --email admin@example.com
if ($LASTEXITCODE -ne 0) {
    Write-Host "   (konto 'admin' juz istnieje - pomijam)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Gotowe. Uruchom aplikacje:" -ForegroundColor Green
Write-Host "   .\.venv\Scripts\python.exe manage.py runserver"
Write-Host "a nastepnie otworz http://127.0.0.1:8000/"
exit 0
