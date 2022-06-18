build:
	go build
	go vet
	-staticcheck

listen: build
	./basicmtls listen :1234 server1.privkey client1.pubkey

dial: build
	./basicmtls dial :1234 client1.privkey server1.pubkey

listen21: build
	./basicmtls listen :1234 server2.privkey client1.pubkey

listen22: build
	./basicmtls listen :1234 server2.privkey client2.pubkey

dial21: build
	./basicmtls dial :1234 client2.privkey server1.pubkey

dial22: build
	./basicmtls dial :1234 client2.privkey server2.pubkey

curl1:
	curl -k https://localhost:1234

curl2:
	curl -v https://localhost:1234

openssl:
	openssl s_client -connect localhost:1234

generate: build
	./basicmtls genkey >server1.privkey
	./basicmtls genkey >server2.privkey
	./basicmtls genkey >client1.privkey
	./basicmtls genkey >client2.privkey
	./basicmtls pubkey <server1.privkey >server1.pubkey
	./basicmtls pubkey <server2.privkey >server2.pubkey
	./basicmtls pubkey <client1.privkey >client1.pubkey
	./basicmtls pubkey <client2.privkey >client2.pubkey

present:
	present -base ${HOME}/go/pkg/mod/golang.org/x/tools@v0.1.11/cmd/present
