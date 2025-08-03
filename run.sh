# define hostname for token service
export SURREALDB_HOSTNAME=localhost
export USER=root
export PASS=root

mkdir mydata # Create a directory to store the database, owned by the current user
docker run --rm --pull always -p 8000:8000 --user $(id -u) -v $(pwd)/mydata:/mydata surrealdb/surrealdb:latest start --log debug --user $USER --pass $PASS rocksdb:/mydata/mydatabase.db --allow-net 