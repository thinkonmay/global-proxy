# Global Proxy Analytics
#### Local Build
```shell
go build -o ~/assets/global 
```

#### Local Run
```shell
sudo ./global -sport [SPORT] -qport [QPORT] -dom [DOMAIN_NAME] -cred [CRED_TOKEN]
```

### Docker build
```shell
docker build -t go-analytics-proxy .
```


### Docker run
```shell
docker run -d \
  -p 8445:8445 \
  -p 50050:50050 \
  -v /home/huyhoang/assets/pb_data/.autocert_cache:/app/pb_data/.autocert_cache \
  go-analytics-proxy \
  -dom yourdomain.com -cred "secret" -sport 8445 -qport 50050

```
---
# Docker
### Build
```shell
docker build -t pigeatgarlic/global-proxy .
```
### Publish
```shell
docker push pigeatgarlic/global-proxy:latest
```