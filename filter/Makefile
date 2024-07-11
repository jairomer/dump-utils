build:
	go build -ldflags '-linkmode external -extldflags -static' .

test:
	echo :P
	time cat ../../rockyou2024 | parallel -j16 --block 200M --pipe ./filter -bigcrypt -blowfish -crypt -des -email -lanman -md5 -nt -sha256 -sha512 -stdin > filtered.txt

clean: 
	rm filtered.txt
