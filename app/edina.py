import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd



def show_edina():
    es = Elasticsearch("http://localhost:9200")
    # es = Elasticsearch("http://elasticsearch:9200")


    # Requête Elasticsearch pour récupérer les logs filtrés
    response = es.search(index="application-logs" )

    # Convertir les résultats en DataFrame
    logs = []
    for hit in response["hits"]["hits"]:
        logs.append(hit["_source"])

    df = pd.DataFrame(logs)

    # Afficher les logs dans un tableau
    st.dataframe(df.head())

    # Afficher des métriques
    st.subheader("Métriques")
    st.write(f"Nombre total de logs : {len(df)}")
