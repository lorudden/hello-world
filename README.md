# hello-world

Testrepo för att labba lite med olika wireup för projektet

## Installera det som behövs

* SSH-nyckel
* Docker
* Git
* Go
* Visual Studio Code

## Starta upp

Öppna en terminal

```bash
git clone git@github.com:lorudden/hello-world.git
cd hello-world

go install github.com/a-h/templ/cmd/templ@latest
templ generate
go run cmd/hello-world/main.go
```

## Titta på resultatet

Surfa till http://localhost:3000
