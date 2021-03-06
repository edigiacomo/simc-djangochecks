# SIMC-djangochecks

Questa app contiene una serie di check per le applicazioni Django sviluppate o
commissionate dal Servizio Idro-Meteo-Clima (SIMC) di Arpae.

## Utilizzo

Aggiungere l'app alle `INSTALLED_APP` dell'applicazione:

```python
# settings.py
# settings.py
INSTALLED_APPS = [
    # ....
    'simc_djangochecks'
]
```

Eseguire il check:

```
$ python manage.py check
```

## Autenticazione e gestione password:

- Hashers: sono da evitare hasher basati su SHA-1 e MD5 e unsalted.
- Uso di `make_password`: si deve usare l'hasher di default
  e il salt generato dal suddetto hasher.
- Validatori per le password (`AUTH_PASSWORD_VALIDATORS`):
  - È necessario usare dei validatori.
  - Sono suggeriti una serie di validatori.
- Uso di `authenticate`: è preferibili usare `LoginView`.
- Backend di autenticazione (`AUTHENTICATION_BACKENDS`) consentiti.

## Validazione dell'input

- Presenza di validatori per `forms.CharField`
- Specifica del range per i field numerici delle form
- Presenza di validatori per `forms.JSONEncoder`
- Presenza di validatori per `forms.FileField`
- Presenza di validatori per `models.CharField` e `models.TextField`
- Specifica del range per i field numerici dei model
- Presenza di validatori per `models.JSONField`
- Uso del decoder e encoder di default per `models.JSONField`
- Uso del modulo `pickle`
- Uso di `exec`
- Uso di `eval`
- Uso di `RawSQL`
- Uso delle keyword `extra` e `extra_content`
- Uso della keyword `shell`

## Validazione dell'output

- Uso di `safe` e `safeseq` nei template
- Uso di `autoescape on`
- Uso di `mark_safe`
- Uso di `DjangoTemplates`
- Disabilitazione dell'autoescape nei settings
- Uso di `HttpResponse` con `Content-Type: text/html`

# Gestione delle sessioni

- Uso del middleware `SessionMiddleware`
- Uso del serializzatore `JSONSerializer` per le sessioni
- Corretta configurazione del session engine:
  - Database: installazione della corrispondente app
  - Filesystem: la directory di salvataggio deve essere
    diversa da `/tmp`, `MEDIA_ROOT` e `STATIC_ROOT`
  - Cache: deve usare Redis
- Uso di cookie-based session: vietato
- Cookie di sessione con attributo `HttpOnly`
- Cookie di sessione con attributo `SameSite=Lax|Strict`
- Cookie di sessione con attributo `Secure`
- Presenza di `CsrfViewMiddleware`
- Uso di `@csrf_exempt`

# Logging

- Passaggio di `X-Request-Id` al logger
- Corretta configurazione per rsyslog in produzione

# Configurazione

- Assegnamento di settings fuori da settings.py
- Hard-coded `SECRET_KEY`
- `ALLOWED_HOSTS` non deve contenere la wildcard `*`
- Informazioni potenzialmente sensibili hard-coded
- Path database SQLite deve essere diverso da `MEDIA_ROOT`, `STATIC_ROOT` o `/var/www/html`
- Database SQLite non deve essere leggibile da `others`
- `DATA_UPLOAD_MAX_MEMORY_SIZE` non deve essere `None`
- `DATA_UPLOAD_MAX_NUMBER_FIELDS` non deve essere `None`
- `DEFAULT_HASHING_ALGORITHM` non deve essere `sha1`
- `FILE_UPLOAD_PERMISSIONS` non deve essere accessibile a `other`
- `FILE_UPLOAD_DIRECTORY_PERMISSIONS` non deve essere accessibile a `other`
- `FILE_UPLOAD_PERMISSIONS` non deve avere permessi di esecuzione
- `FILE_UPLOADED_TEMP_DIR` non deve essere accessibile a `group` e `other`
- `FILE_UPLOADED_TEMP_DIR` non deve essere uguale o contenuto in `MEDIA_ROOT`,
  `STATIC_ROOT` o `/var/www/html`
