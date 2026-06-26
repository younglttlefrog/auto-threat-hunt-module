from app.connectors.opensearch_conn import test_connection, search_alerts

print("=== OpenSearch Info ===")
print(test_connection())

query = {
    "size": 3,
    "sort": [{"@timestamp": {"order": "desc"}}],
    "_source": [
        "@timestamp",
        "agent.name",
        "rule.id",
        "rule.level",
        "rule.description",
        "rule.mitre.id",
        "rule.mitre.tactic",
        "data.srcip",
        "data.url",
        "full_log"
    ],
    "query": {
        "exists": {
            "field": "rule.mitre.id"
        }
    }
}

print("=== Sample MITRE Alerts ===")
res = search_alerts(query)
for hit in res["hits"]["hits"]:
    print(hit["_source"])
