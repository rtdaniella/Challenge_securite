import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd
from st_aggrid import AgGrid, GridOptionsBuilder

def show_data():
    # es = Elasticsearch("http://localhost:9200")
    es = Elasticsearch("http://elasticsearch:9200")

    response = es.search(index="application-logs")

    logs = []
    for hit in response["hits"]["hits"]:
        logs.append(hit["_source"])

    df = pd.DataFrame(logs)

    # Ajouter du style CSS pour l'ensemble de la page
    st.markdown("""
        <style>
            body, .stApp {
                color: #000066; 
                font-family: 'Roboto', sans-serif;
            }
            .title {
                font-size: 36px;
                color: #000066;
                font-weight: bold;
                text-align: center;
                margin-bottom: 20px;
                text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.2);
            }
            .metric-card {
                background-color: #f0f2f6;
                border-radius: 10px;
                padding: 50px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                text-align: center;

                height: 180px;
            }
            .metric-card h3 {
                font-size: 20px;
                color: #4A90E2;
                margin-bottom: 10px;
            }
            .metric-card p {
                font-size: 26px;
                font-weight: bold;
                color: #000066;
                margin: 0;
            }
        </style>
    """, unsafe_allow_html=True)

    # Titre de la page
    st.markdown('<div class="title">🔍 Exploration des Logs</div>', unsafe_allow_html=True)

    # Création de deux colonnes pour les filtres
    col1, col2 = st.columns(2)

    with col1:
        # Filtre pour les protocoles
        protocol_options = df['proto'].unique()
        selected_protocol = st.selectbox("🌐 Sélectionnez un protocole", protocol_options)

    with col2:
        # Filtre pour les actions
        action_options = df['action'].unique()
        selected_action = st.selectbox("🔄 Sélectionnez une action", action_options)

    # Appliquer les filtres aux données si nécessaire
    if selected_protocol:
        df = df[df['proto'] == selected_protocol]
    if selected_action:
        df = df[df['action'] == selected_action]

    # AgGrid Configuration avec du style personnalisé
    st.subheader("📋 Tableau des Logs")
    
    # Configuration de AgGrid avec GridOptionsBuilder
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(enabled=True, paginationPageSize=20)  # Pagination de 20 lignes
    gb.configure_default_column(filterable=True, sortable=True, resizable=True)  # Colonnes filtrables et triables

    # Options de la grille
    grid_options = gb.build()

    # Affichage du tableau avec AgGrid
    AgGrid(df, gridOptions=grid_options, enable_enterprise_modules=True)

    # Création de deux colonnes pour les métriques et les boutons de téléchargement
    col_metrics, col_buttons = st.columns(2)

    with col_metrics:
        # Afficher les métriques dans une carte stylée
        st.markdown("""
            <div class="metric-card">
                <h3>💡 Nombre total de logs</h3>
                <p>{}</p>
            </div>
        """.format(len(df)), unsafe_allow_html=True)

    with col_buttons:
        # Ajouter des boutons de téléchargement avec des styles cool
        st.subheader("⬇️ Téléchargements")
        st.download_button(
            label="Télécharger les logs (CSV)",
            data=df.to_csv(index=False),
            file_name="logs_filtrés.csv",
            mime="text/csv",
            key="csv_download",
            use_container_width=True
        )
        st.download_button(
            label="Télécharger les logs (JSON)",
            data=df.to_json(orient="records"),
            file_name="logs-filtrés.json",
            mime="application/json",
            key="json_download",
            use_container_width=True
        )
