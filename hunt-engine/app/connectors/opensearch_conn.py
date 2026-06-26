
import os

from opensearchpy import OpenSearch

from opensearchpy.helpers import scan



OS_URL = os.getenv("OPENSEARCH_HOST", "127.0.0.1")

OS_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

OS_USER = os.getenv("OPENSEARCH_USER", "admin")

OS_PASS = os.getenv("OPENSEARCH_PASS", "u9foE3W7DWVeefOISrS1*enxY+h+?Lcj")



MAX_ALERT_PIVOT_DOCS = int(os.getenv("MAX_ALERT_PIVOT_DOCS", "5000"))

MAX_ARCHIVE_PIVOT_DOCS = int(os.getenv("MAX_ARCHIVE_PIVOT_DOCS", "10000"))



COMMON_SOURCE = [

    "@timestamp", "agent.name", "rule.id", "rule.level", "rule.description",

    "rule.mitre.id", "rule.mitre.tactic", "data.srcip", "data.dstip",

    "data.srcuser", "data.dstuser", "data.user", "data.url",

    "full_log", "location", "decoder.name"

]



client = OpenSearch(

    hosts=[{"host": OS_URL, "port": OS_PORT}],

    http_auth=(OS_USER, OS_PASS),

    use_ssl=True,

    verify_certs=False,

    ssl_show_warn=False,

)





def agent_filter(agent_names):

    if not agent_names:

        return []

    return [{"terms": {"agent.name": agent_names}}]





def search_all(index, body, page_size=500, max_docs=5000):

    query_body = dict(body)

    query_body["size"] = page_size



    hits = []



    for h in scan(

        client,

        index=index,

        query=query_body,

        size=page_size,

        preserve_order=False,

        request_timeout=120,

    ):

        hits.append(h)

        if len(hits) >= max_docs:

            break



    hits = sorted(hits, key=lambda x: x.get("_source", {}).get("@timestamp", ""))



    return {

        "hits": {"hits": hits},

        "truncated": len(hits) >= max_docs,

    }





def get_level_seeds(time_from="now-24h", time_to="now", min_level=12, size=30, agent_names=None):

    filters = [

        {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},

        {"range": {"rule.level": {"gte": min_level}}},

    ]

    filters.extend(agent_filter(agent_names))



    body = {

        "size": size,

        "sort": [{"@timestamp": {"order": "desc"}}],

        "_source": COMMON_SOURCE,

        "query": {"bool": {"filter": filters}},

    }



    return client.search(index="wazuh-alerts-*", body=body)





def pivot_by_seed(seed, minutes=30, size=200, agent_names=None):

    ts = seed["timestamp"]

    agent = seed.get("agent")

    srcip = seed.get("srcip")



    should = []



    if agent and agent != "-":

        should.append({"term": {"agent.name": agent}})



    if srcip and srcip != "-":

        should.append({"term": {"data.srcip": srcip}})



    filters = [

        {

            "range": {

                "@timestamp": {

                    "gte": f"{ts}||-{minutes}m",

                    "lte": f"{ts}||+{minutes}m",

                }

            }

        }

    ]

    filters.extend(agent_filter(agent_names))



    body = {

        "_source": COMMON_SOURCE,

        "query": {

            "bool": {

                "filter": filters,

                "should": should,

                "minimum_should_match": 1 if should else 0,

            }

        },

    }



    return search_all("wazuh-alerts-*", body, page_size=500, max_docs=MAX_ALERT_PIVOT_DOCS)





def pivot_archives_by_seed(seed, minutes=30, size=1000, agent_names=None):

    ts = seed["timestamp"]

    agent = seed.get("agent")

    srcip = seed.get("srcip")



    should = []



    if agent and agent != "-":

        should.append({"term": {"agent.name": agent}})



    if srcip and srcip != "-":

        should.append({"match_phrase": {"full_log": srcip}})



    filters = [

        {

            "range": {

                "@timestamp": {

                    "gte": f"{ts}||-{minutes}m",

                    "lte": f"{ts}||+{minutes}m",

                }

            }

        }

    ]

    filters.extend(agent_filter(agent_names))



    body = {

        "_source": [

            "@timestamp", "agent.name", "full_log", "location",

            "decoder.name", "data.srcip", "data.dstip",

            "data.srcuser", "data.dstuser", "data.user", "data.url",

        ],

        "query": {

            "bool": {

                "filter": filters,

                "should": should,

                "minimum_should_match": 1 if should else 0,

            }

        },

    }



    return search_all("wazuh-archives-*", body, page_size=500, max_docs=MAX_ARCHIVE_PIVOT_DOCS)

