import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd
from datetime import datetime
from st_aggrid import AgGrid, GridOptionsBuilder
import ipaddress

# ✅ Connexion à Elasticsearch
ES_HOST = "http://localhost:9200"
INDEX_NAME = "application-logs"

# ✅ Fonction pour trier correctement les adresses IP
def sort_ip_list(ip_list):
    try:
        return sorted(ip_list, key=lambda ip: ipaddress.ip_address(ip))
    except ValueError:
        return ip_list  # Si erreur, on ne trie pas

# ✅ Fonction pour récupérer les logs avec cache
@st.cache_data
def load_data_scroll(max_docs=10000, scroll_size=5000):
    es = Elasticsearch(ES_HOST)
    response = es.search(
        index=INDEX_NAME,
        scroll="2m",
        size=scroll_size,
        body={"query": {"match_all": {}}}
    )

    scroll_id = response["_scroll_id"]
    logs = [hit["_source"] for hit in response["hits"]["hits"]]

    while len(logs) < max_docs:
        response = es.scroll(scroll_id=scroll_id, scroll="2m")
        if not response["hits"]["hits"]:
            break  
        logs.extend(hit["_source"] for hit in response["hits"]["hits"])
        if len(logs) >= max_docs:
            break
    es.clear_scroll(scroll_id=scroll_id)
    df = pd.DataFrame(logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['portsrc'] = pd.to_numeric(df['portsrc'], errors='coerce')
    df['portdst'] = pd.to_numeric(df['portdst'], errors='coerce')
    return df

# ✅ Fonction pour réinitialiser tous les filtres
def reset_filters():
    st.session_state["start_hour"] = 0
    st.session_state["start_minute"] = 0
    st.session_state["end_hour"] = 23
    st.session_state["end_minute"] = 59
    st.session_state["selected_protocols"] = []
    st.session_state["selected_actions"] = []
    st.session_state["selected_portsrc"] = []
    st.session_state["selected_portdst"] = []
    st.session_state["selected_ipsrc"] = []
    st.session_state["selected_ipdst"] = []
    
# ✅ Initialisation des valeurs dans `st.session_state`
def initialize_session():
    session_defaults = {
        "max_logs": 10000,
        "start_hour": 0,
        "start_minute": 0,
        "end_hour": 23,
        "end_minute": 59,
        "selected_protocols": [],
        "selected_actions": [],
        "selected_portsrc": [],
        "selected_portdst": [],
        "selected_ipsrc": [],
        "selected_ipdst": []
    }
    for key, default_value in session_defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value


def show_data():
    initialize_session()

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

    # 📌 Slider pour choisir le nombre de logs à charger
    max_logs = st.slider(
        "📊 Nombre de logs à charger", 
        min_value=10000, max_value=700000, step=10000, 
        value=st.session_state["max_logs"]
    )
    st.session_state["max_logs"] = max_logs

    # 🏷️ Charger les données et les mettre en cache
    df = load_data_scroll(max_docs=max_logs)

    st.markdown("<br>", unsafe_allow_html=True)

    # ✅ Sélection des colonnes à afficher
    colonnes_a_afficher = ['ipsrc', 'ipdst', 'portsrc', 'portdst', 'proto', 'action', 'timestamp', 'idregle']
    df = df[colonnes_a_afficher]

    # 📅 Filtres et affichage des logs
    left_col, right_col = st.columns([1, 2])

    with left_col:
        st.markdown("<h6 style='text-align: center;'>Sélectionnez la période</h6>", unsafe_allow_html=True)
        min_date, max_date = df['timestamp'].min().date(), df['timestamp'].max().date()

        col_start_date, col_start_hour, col_start_min = st.columns([2, 1, 1])
        with col_start_date:
            start_date = st.date_input("📆 Début", min_value=min_date, max_value=max_date, value=min_date)

        with col_start_hour:
            start_hour = st.number_input("⏰ Heure", min_value=0, max_value=23, value=st.session_state.get("start_hour", 0), key="start_hour_input")
            st.session_state["start_hour"] = start_hour

        with col_start_min:
            start_minute = st.number_input("🕐 Minute", min_value=0, max_value=59, value=st.session_state.get("start_minute", 0), key="start_minute_input")
            st.session_state["start_minute"] = start_minute

        col_end_date, col_end_hour, col_end_min = st.columns([2, 1, 1])
        with col_end_date:
            end_date = st.date_input("📆 Fin", min_value=min_date, max_value=max_date, value=max_date)

        with col_end_hour:
            end_hour = st.number_input("⏰ Heure", min_value=0, max_value=23, value=st.session_state.get("end_hour", 23), key="end_hour_input")
            st.session_state["end_hour"] = end_hour

        with col_end_min:
            end_minute = st.number_input("🕐 Minute", min_value=0, max_value=59, value=st.session_state.get("end_minute", 59), key="end_minute_input")
            st.session_state["end_minute"] = end_minute

        st.markdown("<br>", unsafe_allow_html=True)
        
        # ✅ Bouton pour réinitialiser les filtres
        if st.button("🔄 Réinitialiser les filtres"):
            reset_filters()
            st.rerun()    

    # ✅ Application du filtre sur la période
    start_datetime = datetime(start_date.year, start_date.month, start_date.day, start_hour, start_minute)
    end_datetime = datetime(end_date.year, end_date.month, end_date.day, end_hour, end_minute, 59)
    df = df[(df['timestamp'] >= start_datetime) & (df['timestamp'] <= end_datetime)]

    st.markdown("<br>", unsafe_allow_html=True)


    with right_col:
        st.markdown("<h6 style='text-align: center;'>Filtres avancés</h6>", unsafe_allow_html=True)

        # ✅ Application des filtres avancés
        col1, col2 = st.columns(2)
        with col1:
            protocol_options = df['proto'].dropna().unique()
            selected_protocols = st.multiselect(
                "🌐 Protocole", protocol_options, default=st.session_state["selected_protocols"]
            )
            st.session_state["selected_protocols"] = selected_protocols
            if selected_protocols:
                df = df[df['proto'].isin(selected_protocols)]

        with col2:
            action_options = df['action'].dropna().unique()
            selected_actions = st.multiselect(
                "🔄 Action", action_options, default=st.session_state["selected_actions"]
            )
            st.session_state["selected_actions"] = selected_actions
            if selected_actions:
                df = df[df['action'].isin(selected_actions)]

        col3, col4, col5 = st.columns(3)
        with col3:
            portsrc_options = sorted(df['portsrc'].dropna().unique())
            selected_portsrc = st.multiselect(
                "🎛️ Ports Source", ["Tout sélectionner"] + portsrc_options, default=st.session_state["selected_portsrc"]
            )
            st.session_state["selected_portsrc"] = selected_portsrc
            if "Tout sélectionner" in selected_portsrc or not selected_portsrc:
                selected_portsrc = portsrc_options  # Si sélection vide ou "Tout sélectionner", prendre tout
            df = df[df['portsrc'].isin(selected_portsrc)]

        with col4:
            # ✅ Ajout du filtre par plage de ports (RFC 6056)
            port_range_filter = st.selectbox(
                "📌 Filtrer par plage de ports", 
                ["Aucune", "Well-Known Ports (0-1023)", "Registered Ports (1024-49151)", "Dynamic/Private Ports (49152-65535)"]
            )

            # Application du filtre par plage
            if port_range_filter == "Well-Known Ports (0-1023)":
                df = df[(df['portdst'] >= 0) & (df['portdst'] <= 1023)]
            elif port_range_filter == "Registered Ports (1024-49151)":
                df = df[(df['portdst'] >= 1024) & (df['portdst'] <= 49151)]
            elif port_range_filter == "Dynamic/Private Ports (49152-65535)":
                df = df[(df['portdst'] >= 49152) & (df['portdst'] <= 65535)]
        with col5:
            # ✅ Filtre par ports individuels
            portdst_options = sorted(df['portdst'].dropna().unique())
            selected_portdst = st.multiselect(
                "🎛️ Ports Destination", ["Tout sélectionner"] + portdst_options, default=st.session_state["selected_portdst"]
            )
            st.session_state["selected_portdst"] = selected_portdst
            if "Tout sélectionner" in selected_portdst or not selected_portdst:
                selected_portdst = portdst_options  # Si sélection vide ou "Tout sélectionner", prendre tout
            df = df[df['portdst'].isin(selected_portdst)]

        col6, col7 = st.columns(2)
        with col6:
            ipsrc_options = sort_ip_list(df['ipsrc'].dropna().unique())
            selected_ipsrc = st.multiselect(
                "🌍 IP Source", ["Tout sélectionner"] + ipsrc_options, default=st.session_state["selected_ipsrc"]
            )
            st.session_state["selected_ipsrc"] = selected_ipsrc
            if "Tout sélectionner" in selected_ipsrc or not selected_ipsrc:
                selected_ipsrc = ipsrc_options  # Si sélection vide ou "Tout sélectionner", prendre tout
            df = df[df['ipsrc'].isin(selected_ipsrc)]

        with col7:
            ipdst_options = sort_ip_list(df['ipdst'].dropna().unique())
            selected_ipdst = st.multiselect(
                "🌎 IP Destination", ["Tout sélectionner"] + ipdst_options, default=st.session_state["selected_ipdst"]
            )
            st.session_state["selected_ipdst"] = selected_ipdst
            if "Tout sélectionner" in selected_ipdst or not selected_ipdst:
                selected_ipdst = ipdst_options  # Si sélection vide ou "Tout sélectionner", prendre tout
            df = df[df['ipdst'].isin(selected_ipdst)]




    st.markdown("<br>", unsafe_allow_html=True)


    # 📋 Affichage du tableau avec AgGrid
    st.subheader("📋 Tableau des Logs")

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(enabled=True, paginationPageSize=20)
    gb.configure_default_column(filterable=True, sortable=True, resizable=True)
    grid_options = gb.build()

    AgGrid(df, gridOptions=grid_options, enable_enterprise_modules=True)



    st.markdown("<br>", unsafe_allow_html=True)

    # 📂 Boutons de téléchargement
    st.subheader("⬇️ Télécharger les logs filtrés")
    st.download_button(
        label="📄 Télécharger CSV", data=df.to_csv(index=False), file_name="logs_filtrés.csv", mime="text/csv"
    )
    st.download_button(
        label="📂 Télécharger JSON", data=df.to_json(orient="records"), file_name="logs_filtrés.json", mime="application/json"
    )

if __name__ == "__main__":
    show_data()



