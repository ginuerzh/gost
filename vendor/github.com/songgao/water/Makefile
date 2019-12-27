.phony: default ci test lint vet gofmt


default:
	echo 'This make file is for CI.'
	exit 1

ci: test lint vet gofmt

test: water.test
	sudo ./water.test -test.v

lint:
	golint -set_exit_status

vet:
	go vet .

gofmt:
	gofmt -s -e -l .

water.test: *.go
	go test -c
