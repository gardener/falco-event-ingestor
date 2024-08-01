PGPASSWORD=$1 psql -h $2 -p $3 -U postgres -c "ALTER USER ${4} WITH PASSWORD '${5}';"
