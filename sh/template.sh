open_id=""
x_api_key=""


curl -X POST http://127.0.0.1/setadmin \
     -H "x-api-key: $x_api_key" \
     -H "Content-Type: application/json" \
     --data-binary "{\"open_id\" : \"$open_id\"}"

curl -X POST http://127.0.0.1/removeadmin \
     -H "x-api-key: $x_api_key" \
     -H "Content-Type: application/json" \
     --data-binary "{\"open_id\" : \"$open_id\"}"

