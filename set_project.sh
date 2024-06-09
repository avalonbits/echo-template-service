#!/bin/bash
for f in $(find ./ -iname "*.go")
do
    sed -e "s/{{project}}\//$1\//g" $f > $f.t
    mv $f.t $f
done


for f in $(find ./ -iname "*.tmpl")
do
    sed -e "s/{{project}}/$1/g" $f > $f.t
    mv $f.t $f
done

sed -e "s/\/{{project}}/\/$1/g" go.mod > go.mod.t
cp go.mod.t go.mod

go mod tidy -v
sqlc generate
go get -u ./...

cat > ./.env<< EOF
DATABASE="/tmp/$1-main.db"
DOMAIN_NAME="localhost"
PORT=1323
BIND_ADDRESS="0.0.0.0"
RECAPTCHA_TOKEN=""
EOF
