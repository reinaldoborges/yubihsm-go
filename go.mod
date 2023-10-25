module github.com/indoff/yubihsm-go

replace github.com/certusone/yubihsm-go => ../yubihsm-go

go 1.14

require (
	github.com/certusone/yubihsm-go v0.0.0-00010101000000-000000000000
	github.com/enceve/crypto v0.0.0-20160707101852-34d48bb93815
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
)
