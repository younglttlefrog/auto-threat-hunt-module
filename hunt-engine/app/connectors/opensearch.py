from opensearchpy import OpenSearch

client = OpenSearch(
    hosts=[{
        "host": "127.0.0.1",
        "port": 9200
    }],
    http_auth=("admin", "PASSWORD"),
    use_ssl=True,
    verify_certs=False
)
