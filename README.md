# hello-world

Testrepo för att labba lite med olika wireup för projektet

## Installera det som behövs

* SSH-nyckel
* Docker ([Mac](https://docs.docker.com/desktop/install/mac-install/) , [Windows](https://docs.docker.com/desktop/install/windows-install/))
* Git
* Go
* Visual Studio Code
* tailwindcss

```
go install github.com/a-h/templ/cmd/templ@latest
go install github.com/cosmtrek/air@latest
```

## Starta upp lokalt

Öppna en terminal

```bash
git clone git@github.com:lorudden/hello-world.git
cd hello-world
code .
air
```

Titta på resultatet genom att surfa till http://localhost:3000

## Starta upp med docker compose

### Skapa våra testdomäner

För att kunna starta upp hemsidan och testa inloggning med mera så behöver du först ändra lite i dina inställningar så att du kan surfa till en påhittad domän som bara finns lokalt på din dator.

Om du har en Mac så ändrar du i /private/etc/hosts och lägger till de här två raderna:

```
127.0.0.1 xn--lrudden-90a.local
127.0.0.1 iam.xn--lrudden-90a.local
```

Om du däremot har en Windows-dator så behöver du lägga till samma rader i C:\Windows\System32\drivers\etc\hosts

### Starta och stoppa compose

```bash
docker compose -f deployments/docker-compose.yaml up --build

# Surfa till https://lörudden.local:8443 för att se resultatet
# Webläsaren kommer att klaga på att certifikatet är ogiltigt, men klicka
# dig fram till sidan ändå, så kommer den att dyka upp

# När du är färdig så stänger du ner allt med det här kommandot
docker compose -f deployments/docker-compose.yaml down -v --remove-orphans
```
