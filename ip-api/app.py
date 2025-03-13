from flask import Flask, Response, jsonify
import requests
import json
from datetime import datetime, timedelta
import os
from elasticsearch import Elasticsearch
import ipaddress

app = Flask(__name__)

ES_HOST = os.getenv('ES_HOST', 'localhost')
ES_PORT = os.getenv('ES_PORT', '9200')
ES_USER = os.getenv('ES_USER', '')
ES_PASS = os.getenv('ES_PASS', '')

def get_elasticsearch_client():
    if ES_USER and ES_PASS:
        return Elasticsearch([f'http://{ES_HOST}:{ES_PORT}'], basic_auth=(ES_USER, ES_PASS))
    else:
        return Elasticsearch([f'http://{ES_HOST}:{ES_PORT}'])

def load_networks_from_file(filename):
    networks = []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                networks.append(ipaddress.IPv4Network(line))
    return networks

def get_attack_ips(time_range):
    es = get_elasticsearch_client()
    
    now = datetime.now()
    
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
        title = "Son 1 Saat İçinde Tespit Edilen Saldırgan IP Adresleri"
    elif time_range == "24h":
        start_time = now - timedelta(hours=24)
        title = "Son 24 Saat İçinde Tespit Edilen Saldırgan IP Adresleri"
    elif time_range == "1w":
        start_time = now - timedelta(weeks=1)
        title = "Son 1 Hafta İçinde Tespit Edilen Saldırgan IP Adresleri"
    elif time_range == "all":
        start_time = now - timedelta(days=365*10)  
        title = "Tüm Zamanlarda Tespit Edilen Saldırgan IP Adresleri"
    else:
        return "Geçersiz zaman aralığı. 1h, 24h, 1w veya all kullanın.", 400
    
    query = {
        "size": 0,  
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "src_ips": {
                "terms": {
                    "field": "src_ip.keyword",
                    "size": 10000  
                }
            }
        }
    }

    
    indices = ["logstash-*", "filebeat-*", "t-pot-*", "*-*"]

    all_ips = set()

    for index in indices:
        try:
            response = es.search(index=index, body=query)

            for bucket in response.get('aggregations', {}).get('src_ips', {}).get('buckets', []):
                ip = bucket.get('key')
                if ip and ip != "":
                    all_ips.add(ip)
        except Exception as e:
            print(f"Error querying index {index}: {str(e)}")

    sorted_ips = sorted(list(all_ips))

    excluded_blocks = load_networks_from_file('networks.txt')

    result = ""

    for ip in sorted_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip)  
            if any(ip_obj in block for block in excluded_blocks):  
                continue
            result += ip + "\n"
        except ipaddress.AddressValueError:
            continue  

    return result

@app.route('/attack-ips/<time_range>', methods=['GET'])
def get_ips(time_range):
    if time_range not in ["1h", "24h", "1w", "all"]:
        return Response("Geçersiz zaman aralığı. 1h, 24h, 1w veya all kullanın.", mimetype="text/plain", status=400)

    result = get_attack_ips(time_range)

    return Response(result, mimetype="text/plain")


@app.route('/attack-ips-download/<time_range>', methods=['GET'])
def get_ips_download(time_range):
    if time_range not in ["1h", "24h", "1w", "all"]:
        return "Geçersiz zaman aralığı. 24h, 1w veya all kullanın.", 400

    result = get_attack_ips(time_range)

    return Response(
        result,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename=attack_ips_{time_range}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
    )

@app.route('/', methods=['GET'])
def index():
   return jsonify({"message": "hello, world"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3131)
