docker network create my-private-network

docker build -t learn-networking:0.0.1 .

docker run -it --rm -v $(pwd):/app -w /app --network my-private-network learn-networking:0.0.1 sh

#docker run -it -rm -v $(pwd)/server:/app -w /app --network my-private-network learn-networking:0.0.1 sh

#docker network rm my-private-network