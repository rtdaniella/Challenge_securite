from elasticsearch import Elasticsearch
import pandas as pd
import traceback  # Pour afficher les erreurs détaillées

# Connexion à Elasticsearch (modifie l'URL si nécessaire)
es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "application-logs"
BATCH_SIZE = 1000  # Nombre d'éléments par batch
 

def get_one_ip_logs(ip):
    """
    Récupère les logs pour une adresse IP source donnée en utilisant la pagination avec `search_after`.
    Seuls les champs spécifiés sont récupérés.
    
    Args:
        ip (str): L'adresse IP source à rechercher.
    
    Returns:
        pd.DataFrame: Un DataFrame contenant les logs correspondants à l'IP avec les champs spécifiés.
    """
    query = {
        "query": {
            "term": {"ipsrc.keyword": ip}  # Filtre par IP source
        },
        "_source": ["interfaceint", "idregle", "ipsrc", "ipdst", "timestamp", "action", "proto", "portdst", "portsrc"],  # Champs à récupérer
        "size": 10000,
        "sort": [{"@timestamp": {"order": "asc"}}]  # Tri par timestamp pour la pagination
    }

    after_key = None
    data = []

    try:
        while True:
            if after_key:
                query["search_after"] = after_key

            result = es.search(index=INDEX_NAME, body=query)
            hits = result["hits"]["hits"]

            if not hits:
                break

            for hit in hits:
                data.append(hit["_source"])

            # Mettre à jour la clé de pagination
            after_key = hits[-1]["sort"]

        df = pd.DataFrame(data)
        print(f"✅ Extraction terminée : {len(df)} résultats récupérés pour l'IP {ip}.")
        return df

    except Exception as e:
        print(f"❌ Erreur lors de la requête Elasticsearch: {e}")
        traceback.print_exc()
        return pd.DataFrame()  # Retourne un DataFrame vide en cas d'erreur
    




def permit_deny_by_ip():
    """Récupère le nombre de PERMIT et DENY par IP source en paginant avec composite."""
    query = {
        "size": 0,
        "aggs": {
            "group_by_ip": {
                "composite": {
                    "size": BATCH_SIZE,
                    "sources": [
                        {"ipsrc": {"terms": {"field": "ipsrc.keyword"}}}
                    ]
                },
                "aggs": {
                    "permit": {"filter": {"term": {"action.keyword": "PERMIT"}}},
                    "deny": {"filter": {"term": {"action.keyword": "DENY"}}},

                    "permit_proto_TCP": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"term": {"action.keyword": "PERMIT"}},
                                    {"term": {"proto.keyword": "TCP"}}
                                ]
                            }
                        }
                    },
                    "permit_proto_UDP": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"term": {"action.keyword": "PERMIT"}},
                                    {"term": {"proto.keyword": "UDP"}}
                                ]
                            }
                        }
                    },

                    "nombre_port_dest": {"cardinality": {"field": "portdst.keyword"}},
                    "nombre_port_src": {"cardinality": {"field": "portsrc.keyword"}},

                    # Classification des ports
                    "port_dst_well_known": {"filter": {"range": {"portdst.keyword": {"lte": 1023}}}},
                    "port_dst_registered": {"filter": {"range": {"portdst.keyword": {"gte": 1024, "lte": 49151}}}},
                    "port_dst_dynamic_private": {"filter": {"range": {"portdst.keyword": {"gte": 49152}}}},
                },
            }
        }
    }

    after_key = None
    data = []

    try:
        while True:
            if after_key:
                query["aggs"]["group_by_ip"]["composite"]["after"] = after_key

            result = es.search(index=INDEX_NAME, body=query)
            buckets = result["aggregations"]["group_by_ip"]["buckets"]

            if not buckets:
                break

            for bucket in buckets:
                data.append({
                    "IP_Source": bucket["key"]["ipsrc"],
                    "COUNT": bucket["doc_count"],
                    "PERMIT": bucket["permit"]["doc_count"],
                    "PERMIT_TCP": bucket["permit_proto_TCP"]["doc_count"],
                    "PERMIT_UDP": bucket["permit_proto_UDP"]["doc_count"],
                    "DENY": bucket["deny"]["doc_count"],
                    "Nb_Port_Dest": bucket["nombre_port_dest"]["value"],
                    "Nb_Port_Src": bucket["nombre_port_src"]["value"],
                    "Port_Dest_Well_Known": bucket["port_dst_well_known"]["doc_count"],
                    "Port_Dest_Registered": bucket["port_dst_registered"]["doc_count"],
                    "Port_Dest_Dynamic_Private": bucket["port_dst_dynamic_private"]["doc_count"],
                })

            after_key = result["aggregations"]["group_by_ip"].get("after_key")

        df = pd.DataFrame(data)
        print(f"✅ Extraction terminée : {len(df)} résultats récupérés.")
        return df

    except Exception as e:
        print(f"❌ Erreur lors de la requête Elasticsearch: {e}")
        traceback.print_exc()
        return pd.DataFrame()


# # Exécuter la fonction et afficher un aperçu des résultats
# df_permit_deny = permit_deny_by_ip()

# # Sauvegarde optionnelle en CSV
# # df_permit_deny.to_csv("resultats_permit_deny.csv", index=False)

# df_permit_deny.head()
