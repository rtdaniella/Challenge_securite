import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import datetime

# Fonction pour charger les données depuis Elasticsearch avec mise en cache
@st.cache_data
def load_data():
    es = Elasticsearch("http://localhost:9200")
    response = es.search(index="application-logs", size=5000, body={"query": {"match_all": {}}})
    logs = [hit["_source"] for hit in response["hits"]["hits"]]
    return pd.DataFrame(logs)

def show_linhnhi():
    st.markdown("<h2 style='text-align: center;'>🔍 Analyse Linh Nhi - Filtres interactifs</h2>", unsafe_allow_html=True)

    df = load_data()

    # Sélection des colonnes à afficher
    colonnes_a_afficher = ['ipsrc', 'ipdst', 'portsrc', 'portdst', 'proto', 'action', 'timestamp', 'idregle', 'interfaceint']
    df = df[colonnes_a_afficher]

    # Convertir timestamp en datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # 🔹 **Filtres interactifs organisés proprement**
    with st.expander("🎛️ **Filtres avancés**", expanded=True):
        col1, col2, col3 = st.columns(3)

        with col1:
            # Sélection du protocole (Multi-sélection)
            protos_disponibles = sorted(df['proto'].dropna().unique())
            selected_protos = st.multiselect("📡 Protocole", protos_disponibles, default=protos_disponibles)

        with col2:
            # Sélection de l'action (PERMIT / DENY)
            actions_disponibles = df['action'].dropna().unique()
            selected_action = st.selectbox("🔰 Action", ["Tous"] + list(actions_disponibles))

        with col3:
            # Filtre sur l'interface
            interfaces_disponibles = df['interfaceint'].dropna().unique()
            selected_interface = st.selectbox("🌐 Interface", ["Tous"] + list(interfaces_disponibles))

        col4, col5 = st.columns(2)

        with col4:
            # Sélection du port source
            portsrc_input = st.text_input("🎯 Filtrer par Port Source", "")

        with col5:
            # Sélection du port destination
            portdst_input = st.text_input("🎯 Filtrer par Port Destination", "")

        # 🔹 **Filtrage par plage de date et heure**
        st.markdown("### 🕒 **Filtrage par Date & Heure**")

        col6, col7, col8, col9 = st.columns(4)

        with col6:
            min_date, max_date = df['timestamp'].min().date(), df['timestamp'].max().date()
            selected_start_date = st.date_input("📆 Date de début", min_date, min_value=min_date, max_value=max_date)

        with col7:
            selected_start_time = st.time_input("🕓 Heure de début", datetime.time(0, 0))

        with col8:
            selected_end_date = st.date_input("📆 Date de fin", max_date, min_value=min_date, max_value=max_date)

        with col9:
            selected_end_time = st.time_input("🕘 Heure de fin", datetime.time(23, 59))

    # 🔹 **Appliquer les filtres**
    df_filtered = df[df['proto'].isin(selected_protos)]

    if selected_action != "Tous":
        df_filtered = df_filtered[df_filtered['action'] == selected_action]

    if selected_interface != "Tous":
        df_filtered = df_filtered[df_filtered['interfaceint'] == selected_interface]

    if portsrc_input:
        df_filtered = df_filtered[df_filtered['portsrc'] == int(portsrc_input)]

    if portdst_input:
        df_filtered = df_filtered[df_filtered['portdst'] == int(portdst_input)]

    # Convertir les sélections de date et heure en `datetime`
    start_datetime = datetime.datetime.combine(selected_start_date, selected_start_time)
    end_datetime = datetime.datetime.combine(selected_end_date, selected_end_time)

    df_filtered = df_filtered[(df_filtered['timestamp'] >= start_datetime) & (df_filtered['timestamp'] <= end_datetime)]

    # 📌 **Pagination**
    page_size = 50
    total_pages = max((len(df_filtered) - 1) // page_size + 1, 1)

    col1, col2 = st.columns([3, 1])
    with col1:
        page = st.slider("📄 Sélectionner la page", min_value=1, max_value=total_pages, value=1)

    # Calcul des indices pour afficher les données
    start = (page - 1) * page_size
    end = start + page_size

    # 🔹 **Affichage du DataFrame paginé**
    st.dataframe(df_filtered.iloc[start:end], use_container_width=True, height=400)

    # 🔹 **Boutons de navigation alignés sous le tableau**
    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        if st.button("⬅️ Précédent") and page > 1:
            page -= 1

    with col2:
        st.markdown(f"<div style='text-align:center; font-size:18px;'>📄 Page <b>{page}</b> / <b>{total_pages}</b></div>", unsafe_allow_html=True)

    with col3:
        if st.button("Suivant ➡️") and page < total_pages:
            page += 1

    st.caption(f"Affichage des lignes {start + 1} à {min(end, len(df_filtered))} sur {len(df_filtered)}")





    # Histogramme global des protocoles
    st.subheader("Distribution des protocoles (tous flux)")
    fig_proto = px.histogram(df, x='proto',
                             labels={'proto': 'Protocole', 'count': 'Nombre d’occurrences'},
                             text_auto=True)
    st.plotly_chart(fig_proto, use_container_width=True, key="proto_all")

    # Histogramme des flux rejetés
    df_deny = df[df['action'] == 'DENY']

    if not df_deny.empty:
        st.subheader("Protocoles des flux rejetés")
        fig_deny = px.histogram(df_deny, x='proto',
                                labels={'proto': 'Protocole', 'count': 'Nombre de rejets'},
                                color_discrete_sequence=['#EF553B'],
                                text_auto=True)
        st.plotly_chart(fig_deny, use_container_width=True, key="proto_deny_hist")
    else:
        st.info("Aucun flux rejeté trouvé.")

    # Histogramme des flux acceptés
    df_permit = df[df['action'] == 'PERMIT']

    if not df_permit.empty:
        st.subheader("Protocoles des flux acceptés")
        fig_permit = px.histogram(df_permit, x='proto',
                                  labels={'proto': 'Protocole', 'count': 'Nombre d’occurrences'},
                                  text_auto=True)
        st.plotly_chart(fig_permit, use_container_width=True, key="proto_permit_hist")
    else:
        st.info("Aucun flux accepté trouvé.")


    import plotly.graph_objects as go

    # Sélection des 5 IP les plus fréquentes
    top_ipdst = df['ipdst'].value_counts().head(5).reset_index()
    top_ipdst.columns = ['IP Destination', 'Nombre d’occurrences']

    # Création du tableau Plotly
    fig = go.Figure(data=[go.Table(
        header=dict(
            values=['IP Destination', 'Nombre d’occurrences'],
            fill_color='lightblue',
            align='center',
            font=dict(color='black', size=16)
        ),
        cells=dict(
            values=[top_ipdst['IP Destination'], top_ipdst['Nombre d’occurrences']],
            fill_color='lavender',
            align='center',
            font=dict(color='black', size=13)
        )
    )])

    st.subheader("Top 5 IP Destination les plus fréquentes")
    st.plotly_chart(fig, use_container_width=True)


    # Top 5 IP sources
    top_ipsrc = df['ipsrc'].value_counts().head(5).reset_index()
    top_ipsrc.columns = ['IP Source', 'Nombre d’occurrences']

    fig_ipsrc = go.Figure(data=[go.Table(
        header=dict(values=['IP Source', 'Nombre d’occurrences'],
                    fill_color='paleturquoise',
                    align='center',
                    font=dict(size=14)),
        cells=dict(values=[top_ipsrc['IP Source'], top_ipsrc['Nombre d’occurrences']],
                fill_color='lavender',
                align='center',
                font=dict(color='black', size=13))
    )])

    st.subheader("Top 5 IP Source les plus fréquentes")
    st.plotly_chart(fig_ipsrc, use_container_width=True)


    # Top 5 ports destination pour les flux acceptés (action != 'Deny')
    df_permit = df[df['action'] =='PERMIT']

    top_portsdst_permit = df_permit['portdst'].value_counts().head(5).reset_index()
    top_portsdst_permit.columns = ['Port Destination', 'Nombre d’occurrences']

    fig_portsdst = go.Figure(data=[go.Table(
        header=dict(values=['Port Destination', 'Nombre d’occurrences'],
                    fill_color='lightgreen',
                    align='center',
                    font=dict(size=14)),
        cells=dict(values=[top_portsdst_permit['Port Destination'], top_portsdst_permit['Nombre d’occurrences']],
                fill_color='mintcream',
                align='center',
                font=dict(color='black', size=13))
    )])

    st.subheader("Top 5 Ports Destination les plus utilisés (action = Permit)")
    st.plotly_chart(fig_portsdst, use_container_width=True)


    # Top 5 ports destination pour les flux rejetés (action == 'Deny')
    df_deny = df[df['action'] == 'DENY']

    top_portsdst_deny = df_deny['portdst'].value_counts().head(5).reset_index()
    top_portsdst_deny.columns = ['Port Destination', 'Nombre d’occurrences']

    fig_portsdst_deny = go.Figure(data=[go.Table(
        header=dict(values=['Port Destination', 'Nombre d’occurrences'],
                    fill_color='lightcoral',
                    align='center',
                    font=dict(size=14)),
        cells=dict(values=[top_portsdst_deny['Port Destination'], top_portsdst_deny['Nombre d’occurrences']],
                fill_color='mistyrose',
                align='center',
                font=dict(color='black', size=13))
    )])

    st.subheader("Top 5 Ports Destination les plus rejetés (action = Deny)")
    st.plotly_chart(fig_portsdst_deny, use_container_width=True)

    # Filtre sur les ports d'administration et action = Permit
    admin_ports = [21, 22, 23, 3306, 3389]
    df_admin_permit = df[(df['portdst'].isin(admin_ports)) & (df['action'] == 'PERMIT')]

    # Top 5 IP sources utilisant les ports d'administration
    top_admin_ipsrc = df_admin_permit['ipsrc'].value_counts().head(5).reset_index()
    top_admin_ipsrc.columns = ['IP Source', 'Nombre d’utilisations']

    fig_admin_ipsrc = go.Figure(data=[go.Table(
        header=dict(values=['IP Source', 'Nombre d’utilisations'],
                    fill_color='orange',
                    align='center',
                    font=dict(size=14)),
        cells=dict(values=[top_admin_ipsrc['IP Source'], top_admin_ipsrc['Nombre d’utilisations']],
                fill_color='floralwhite',
                align='center',
                font=dict(color='black', size=13))
    )])

    st.subheader("Top 5 IP sources utilisant les ports d'administration (Permit)")
    st.plotly_chart(fig_admin_ipsrc, use_container_width=True)



    # Filtre sur les ports d'administration (sans filtrer l'action)
    admin_ports = [21, 22, 23, 3306, 3389]
    df_admin_ipdst = df[df['portdst'].isin(admin_ports)]

    # Top 5 IP destinations les plus sollicitées sur ces ports
    top_admin_ipdst = df_admin_ipdst['ipdst'].value_counts().head(5).reset_index()
    top_admin_ipdst.columns = ['IP Destination', 'Nombre de sollicitations']

    fig_admin_ipdst = go.Figure(data=[go.Table(
        header=dict(values=['IP Destination', 'Nombre de sollicitations'],
                    fill_color='mediumorchid',
                    align='center',
                    font=dict(size=14, color='white')),
        cells=dict(values=[top_admin_ipdst['IP Destination'], top_admin_ipdst['Nombre de sollicitations']],
                fill_color='thistle',
                align='center',
                font=dict(color='black', size=13))
    )])

    st.subheader("Top 5 IP destination sollicitées sur les ports d'administration")
    st.plotly_chart(fig_admin_ipdst, use_container_width=True)
