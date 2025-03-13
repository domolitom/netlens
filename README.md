# netlens

Create a docker network and attach containers to it.

```
docker network create my-private-network
```

```
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  golang:alpine sh
```

```
docker network rm my-private-network
```
