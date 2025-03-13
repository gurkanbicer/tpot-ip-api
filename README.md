# tpot-ip-api
An API for T-POT

### Setup

```
cd tpot-ip-api
docker-compose build
docker-compose up -d
docker-logs ip-api -f
```

### API Endpoints;

```
http://IP:3131/attack-ips/1h
http://IP:3131/attack-ips/24h
http://IP:3131/attack-ips/1w
http://IP:3131/attack-ips/all
```
