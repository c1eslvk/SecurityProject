# System autoryzacji RBAC

Webowy system autoryzacji, którego sednem jest **warstwa bezpieczeństwa**: pokazuje
ścisłą, egzekwowaną po stronie serwera kontrolę dostępu opartą na rolach (RBAC)
na bazie Django + Django REST Framework, z uwierzytelnianiem JWT w ciasteczkach
HttpOnly, logowaniem zdarzeń i prostym interfejsem z paskiem nawigacji oraz
stronami zależnymi od roli.

## Co robi aplikacja

- **Rejestracja** lub **logowanie** (nazwa użytkownika + hasło).
- Strona **Home** pokazuje aktualne role zalogowanego użytkownika.
- Strony **User**, **Manager**, **Admin** w pasku nawigacji, dostępne zależnie od roli:
  - **User** widzi: Home, User.
  - **Manager** widzi: Home, User, Manager.
  - **Admin** widzi: Home, User, Manager, Admin.
- Strona **User** wyświetla `Hello on User page <login>`, a strona **Manager** analogicznie.
- Strona **Admin** wyświetla listę wszystkich użytkowników; administrator może
  **nadawać i odbierać role** oraz **usuwać użytkowników**.

Każde nowe konto otrzymuje bazową rolę **User** automatycznie — tej roli nie da
się nadać ani odebrać przez API. Role **Manager** i **Admin** nadaje administrator.

## Stack technologiczny

| Obszar               | Wybór                                                              |
|----------------------|-------------------------------------------------------------------|
| Język / framework    | Python 3.12, Django 5.1, Django REST Framework                    |
| Uwierzytelnianie     | JWT (SimpleJWT) w ciasteczkach **HttpOnly**, z rotacją i unieważnianiem |
| Hashowanie haseł     | **Argon2id** (`argon2-cffi`)                                      |
| Autoryzacja          | Grupy Django = **role**, uprawnienia Django = **możliwości**       |
| Nagłówki bezpieczeństwa | `SecurityMiddleware` + `django-csp` + ochrona przed clickjackingiem |
| Baza danych          | SQLite (zero konfiguracji)                                        |
| Frontend             | Jedna strona renderowana serwerowo + czysty JS (SPA, zgodny z CSP) |

## Szybki start

Pierwsze uruchomienie — jeden skrypt (Windows / PowerShell):

```powershell
.\setup.ps1
```

Skrypt utworzy środowisko wirtualne, zainstaluje zależności, przygotuje plik
`.env`, bazę danych, role oraz konto administratora (wypisze wygenerowane hasło).

Albo te same kroki ręcznie:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py seed_rbac
.\.venv\Scripts\python.exe manage.py bootstrap_admin --username admin --email admin@example.com
```

Uruchomienie aplikacji:

```powershell
.\.venv\Scripts\python.exe manage.py runserver
```

Następnie otwórz **http://127.0.0.1:8000/**.

## Role i uprawnienia

Role to **grupy** Django, a kod nigdy nie sprawdza nazwy roli — sprawdza
**uprawnienie**. Definicja znajduje się w jednym miejscu: `accounts/permissions.py`
(`ROLES`), a polecenie `seed_rbac` zamienia ją na grupy.

| Uprawnienie                      | User | Manager | Admin |
|----------------------------------|:----:|:-------:|:-----:|
| `accounts.access_user_page`      |  ✅  |   ✅    |  ✅   |
| `accounts.access_manager_page`   |      |   ✅    |  ✅   |
| `accounts.access_admin_page`     |      |         |  ✅   |
| `accounts.view_users`            |      |         |  ✅   |
| `accounts.manage_roles`          |      |         |  ✅   |
| `accounts.delete_users`          |      |         |  ✅   |

Dostęp jest hierarchiczny, ponieważ wyższe role zawierają uprawnienia niższych.

Zasady chroniące przed eskalacją uprawnień (egzekwowane po stronie serwera):

- Tylko administrator (z uprawnieniem `manage_roles` / `delete_users`) może
  zmieniać role lub usuwać konta.
- **Nie można zmienić własnych ról ani usunąć własnego konta.**
- **Nie można działać na koncie o wyższych uprawnieniach** (superużytkownik lub
  inny admin), chyba że samemu jest się superużytkownikiem.
- Nadawać można tylko role `Manager` i `Admin`; bazowej roli `User` ani statusu
  superużytkownika/staff nie da się przyznać przez API.
- Każda zmiana ról **unieważnia istniejące tokeny** danego użytkownika.

## Testowanie ręczne w przeglądarce

Uruchom serwer (`runserver`) i otwórz http://127.0.0.1:8000/.

1. **Rejestracja i role bazowe.** Kliknij *Create account*, załóż konto i zaloguj
   się. Na stronie **Home** zobaczysz, że masz tylko rolę `User`. W pasku
   nawigacji widoczne są jedynie **Home** i **User** — odnośniki do **Manager** i
   **Admin** są ukryte.
2. **Strona User.** Wejdź na **User** — zobaczysz `Hello on User page <twój login>`.
3. **Nadawanie ról (jako admin).** Zaloguj się jako **admin** (login i hasło z
   kroku instalacji), wejdź na stronę **Admin**, zaznacz `Manager` lub `Admin`
   przy wybranym użytkowniku i kliknij *Save roles*. Możesz też **usunąć**
   użytkownika.
4. **Hierarchia dostępu.** Zaloguj się ponownie jako ten użytkownik — pojawią się
   nowe strony zgodne z nadaną rolą.
5. **Dowód egzekwowania po stronie serwera (kluczowe dla bezpieczeństwa).**
   Zaloguj się jako zwykły **User** i wpisz bezpośrednio w pasku adresu:

   ```
   http://127.0.0.1:8000/api/auth/users/
   ```

   Mimo że interfejs ukrył odnośnik *Admin*, serwer i tak odrzuca żądanie —
   zwraca **HTTP 403** z treścią
   `{"detail": "You do not have permission to access this resource."}`.
   To pokazuje, że granicą bezpieczeństwa jest serwer, a nie interfejs.

## Bezpieczeństwo (najważniejsze)

- **Domyślny brak dostępu** — każde żądanie wymaga jawnego uprawnienia; brak
  reguły = brak dostępu.
- **Autoryzacja po stronie serwera przy każdym żądaniu** — interfejs jedynie
  ukrywa elementy, faktyczną kontrolę robi serwer.
- **Sprawdzanie uprawnień, nie nazw ról** (`user.has_perm(...)`).
- **Brak IDOR / eskalacji uprawnień** — operacje na konkretnym użytkowniku
  weryfikują prawa wobec tego konkretnego konta.
- **Hasła** — Argon2id, minimum 12 znaków, walidatory Django; brak szybkich/
  niesolonych skrótów.
- **Ograniczanie prób logowania** — limit na IP oraz blokada konta po 5 nieudanych próbach.
- **Nagłówki** — CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  HSTS (po HTTPS); aplikacji nie da się osadzić w ramce.
- **Ciasteczka / tokeny** — JWT podpisane, w ciasteczkach `HttpOnly`, `Secure`,
  `SameSite=Strict`; świeże tokeny przy logowaniu, pełne unieważnienie przy
  wylogowaniu, limity czasu (10 min dostęp / 8 h odświeżanie).
- **Logowanie zdarzeń** — strukturalne logi (logowania, wylogowania, zmiany ról,
  usunięcia kont, odmowy dostępu); bez haseł, tokenów i sekretów.
- **Konfiguracja** — sekrety w zmiennych środowiskowych / `.env` (poza repozytorium).
