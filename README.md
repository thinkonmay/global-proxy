```shell
go build -o ~/assets/global 
```

```shell
sudo ./global -sport [SPORT] -qport [QPORT] -dom [DOMAIN_NAME] -cred [CRED_TOKEN]
```

```shell
#Docker build
docker build -t go-analytics-proxy .
```


```shell
#Docker run
docker run -d \
  -p 8445:8445 \
  -p 50050:50050 \
  -v /home/huyhoang/assets/pb_data/.autocert_cache:/app/pb_data/.autocert_cache \
  go-analytics-proxy \
  -dom yourdomain.com -cred "secret" -sport 8445 -qport 50050

```
