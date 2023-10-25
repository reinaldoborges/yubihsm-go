module github.com/indoff/yubihsm-go

replace github.com/certusone/yubihsm-go => ../yubihsm-go

go 1.19

require (
	github.com/certusone/yubihsm-go v0.3.0
	github.com/enceve/crypto v0.0.0-20160707101852-34d48bb93815
	golang.org/x/crypto v0.14.0
)
