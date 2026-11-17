# payload

Desktop builds embed the static linux/amd64 server binary here as
`hestia-linux-amd64` (see `make desktop`). The binary is git-ignored; without
it the desktop build still compiles, but installing Hestia on a server fails
with a clear message.
