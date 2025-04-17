#!/bin/bash

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi


if ! docker ps | grep -q "part_auth_service_container"; then
    docker run --name part_auth_service_container \
        -e POSTGRES_USER=$POSTGRES_USER \
        -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
        -e POSTGRES_DB=$POSTGRES_DB \
        -p $POSTGRES_PORT:$POSTGRES_PORT \
        -d postgres:15
fi

if ! docker ps | grep -q "part_auth_service_container"; then
    echo "part_auth_service_container не запущен"
    exit 1
fi

until docker exec -i part_auth_service_container pg_isready -U $POSTGRES_USER > /dev/null 2>&1; do
    sleep 1
done

DB_EXISTS=$(docker exec -i part_auth_service_container psql -h localhost -p $POSTGRES_PORT -U $POSTGRES_USER -lqt | cut -d \| -f 1 | grep -w "$POSTGRES_DB")
if [ -z "$DB_EXISTS" ]; then
    docker exec -i part_auth_service_container psql -h localhost -p $POSTGRES_PORT -U $POSTGRES_USER -c "CREATE DATABASE $POSTGRES_DB;"
fi

docker run -it --rm \
    --network host \
    --volume "$(pwd)/db/migrations:/migrations" \
    migrate/migrate:v4.17.0 \
    -path="/migrations" \
    -database "postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable" \
    up
