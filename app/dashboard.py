import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import traceback
import plotly.express as px

# Connexion à Elasticsearch
es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "application-logs"
BATCH_SIZE = 1000  # Nombre d'éléments par batch

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

def show_dashboard():
    # Connexion à Elasticsearch et extraction des données
    df = permit_deny_by_ip()

    if df.empty:
        st.error("❌ Aucune donnée récupérée.")
        return

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
            .kpi-card {
                font-size: 24px;
                font-weight: bold;
                text-align: center;
                padding: 20px;
                background-color: #000066;
                border-radius: 15px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                margin: 10px;
                height: 160px;
                color: white;
            }
            .kpi-card:hover {
                transform: translateY(-10px);
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
            }
            .kpi-value {
                font-size: 40px;
                color: #4CAF50;
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="title">🕸️ Analyse et Visualisation des flux réseaux</div>', unsafe_allow_html=True)

    # Filtres : Protocole, Plage de ports
    st.subheader("Filtres")
    
    # Créer 2 colonnes pour les filtres
    col1, col2 = st.columns(2)

    with col1:
        # Créer un filtre pour le protocole
        protocol_options = ['TCP', 'UDP']
        selected_protocol = st.selectbox("🔌 Sélectionnez un protocole", protocol_options)

    with col2:
        # Créer un filtre pour la plage de port selon la RFC 6056
        port_group_options = ['Bien connus (0-1023)', 'Enregistrés (1024-49151)', 'Dynamiques/Privés (49152-65535)']
        selected_port_group = st.selectbox("⚙️ Sélectionnez une plage de port", port_group_options)

    # Filtrer le DataFrame selon les sélections
    filtered_df = df

    # Filtrer par protocole
    if selected_protocol:
        filtered_df = filtered_df[filtered_df['PERMIT_' + selected_protocol].notna()]

    # Filtrer par plage de port
    if selected_port_group == 'Bien connus (0-1023)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Well_Known'] > 0]
    elif selected_port_group == 'Enregistrés (1024-49151)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Registered'] > 0]
    elif selected_port_group == 'Dynamiques/Privés (49152-65535)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Dynamic_Private'] > 0]

    # Créer 3 colonnes pour les KPI
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{filtered_df['PERMIT'].sum()}</div>
                <p>✅ Flux autorisés</p>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{filtered_df['DENY'].sum()}</div>
                <p>❌ Flux rejetés</p>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        rejection_rate = (filtered_df['DENY'].sum() / (filtered_df['PERMIT'].sum() + filtered_df['DENY'].sum())) * 100 if len(filtered_df) > 0 else 0
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{rejection_rate:.2f} %</div>
                <p>⚠️ Taux de rejet</p>
            </div>
        """, unsafe_allow_html=True)
    
    # Créer 2 colonnes pour la visualisation
    col1, col2 = st.columns(2)
    
    import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import traceback
import plotly.express as px

# Connexion à Elasticsearch
es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "application-logs"
BATCH_SIZE = 1000  # Nombre d'éléments par batch

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

def show_dashboard():
    # Connexion à Elasticsearch et extraction des données
    df = permit_deny_by_ip()

    if df.empty:
        st.error("❌ Aucune donnée récupérée.")
        return

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
            .kpi-card {
                font-size: 24px;
                font-weight: bold;
                text-align: center;
                padding: 20px;
                background-color: #000066;
                border-radius: 15px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                margin: 10px;
                height: 160px;
                color: white;
            }
            .kpi-card:hover {
                transform: translateY(-10px);
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
            }
            .kpi-value {
                font-size: 40px;
                color: #4CAF50;
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="title">🕸️ Analyse et Visualisation des flux réseaux</div>', unsafe_allow_html=True)

    # Filtres : Protocole, Plage de ports
    st.subheader("Filtres")
    
    # Créer 2 colonnes pour les filtres
    col1, col2 = st.columns(2)

    with col1:
        # Créer un filtre pour le protocole
        protocol_options = ['TCP', 'UDP']
        selected_protocol = st.selectbox("🔌 Sélectionnez un protocole", protocol_options)

    with col2:
        # Créer un filtre pour la plage de port selon la RFC 6056
        port_group_options = ['Bien connus (0-1023)', 'Enregistrés (1024-49151)', 'Dynamiques/Privés (49152-65535)']
        selected_port_group = st.selectbox("⚙️ Sélectionnez une plage de port", port_group_options)

    # Filtrer le DataFrame selon les sélections
    filtered_df = df

    # Filtrer par protocole
    if selected_protocol:
        filtered_df = filtered_df[filtered_df['PERMIT_' + selected_protocol].notna()]

    # Filtrer par plage de port
    if selected_port_group == 'Bien connus (0-1023)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Well_Known'] > 0]
    elif selected_port_group == 'Enregistrés (1024-49151)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Registered'] > 0]
    elif selected_port_group == 'Dynamiques/Privés (49152-65535)':
        filtered_df = filtered_df[filtered_df['Port_Dest_Dynamic_Private'] > 0]

    # Créer 3 colonnes pour les KPI
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{filtered_df['PERMIT'].sum()}</div>
                <p>✅ Flux autorisés</p>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{filtered_df['DENY'].sum()}</div>
                <p>❌ Flux rejetés</p>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        rejection_rate = (filtered_df['DENY'].sum() / (filtered_df['PERMIT'].sum() + filtered_df['DENY'].sum())) * 100 if len(filtered_df) > 0 else 0
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{rejection_rate:.2f} %</div>
                <p>⚠️ Taux de rejet</p>
            </div>
        """, unsafe_allow_html=True)
    
    # Créer 2 colonnes pour la visualisation
    col1, col2 = st.columns(2)
    
    with col1:
            # Graphique Pie Chart
            fig_pie = px.pie(
                df, 
                names=["PERMIT", "DENY"],
                values=[df["PERMIT"].sum(), df["DENY"].sum()],
                title="Répartition des Flux (Autorisé vs Rejeté)",
                color_discrete_sequence=["#2ECC71", "#E74C3C"],  # Vert et rouge
            )
            fig_pie.update_traces(textinfo='percent+label')  # Effet détaché

            st.markdown('<div class="graph-container">', unsafe_allow_html=True)
            st.plotly_chart(fig_pie, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

    with col2:
            # Graphique Bar Chart amélioré
            fig_bar = go.Figure()
            fig_bar.add_trace(go.Bar(
                x=df["IP_Source"],
                y=df["PERMIT"],
                name="Autorisé (PERMIT)",
                marker_color="#3498DB",  # Bleu
            ))
            fig_bar.add_trace(go.Bar(
                x=df["IP_Source"],
                y=df["DENY"],
                name="Rejeté (DENY)",
                marker_color="#E74C3C",  # Rouge
            ))

            fig_bar.update_layout(
                title="Nombre de Flux par IP Source",
                xaxis_title="IP Source",
                yaxis_title="Nombre de Flux",
                legend_title="Action",
                template="plotly_white",
                barmode="group",
                xaxis_tickangle=-45,
                margin=dict(l=40, r=40, t=50, b=100)
            )

            st.markdown('<div class="graph-container">', unsafe_allow_html=True)
            st.plotly_chart(fig_bar, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

