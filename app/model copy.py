import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from st_aggrid import AgGrid, GridOptionsBuilder
import plotly.graph_objects as go
from  utils import permit_deny_by_ip

# Constantes
FEATURES = [
    "COUNT", "PERMIT", "DENY", "PERMIT_TCP", "PERMIT_UDP", 
    "Nb_Port_Dest", "Nb_Port_Src", "Port_Dest_Well_Known", 
    "Port_Dest_Registered", "Port_Dest_Dynamic_Private"
]

CUSTOM_THEME = {
    'primary_color': '#000066',
    'background_color': '#f0f2f6',
    'text_color': '#1f1f1f',
    'font_family': 'Roboto, sans-serif'
}

# def setup_page_config():
#     st.set_page_config(
#         page_title="Analyse de Logs - ML Dashboard",
#         page_icon="🕸️",
#         layout="wide"
#     )

def apply_custom_css():
    st.markdown("""
        <style>
            .stApp {
                background-color: ${background_color};
            }
            .title {
                font-size: 42px;
                color: ${primary_color};
                font-weight: bold;
                text-align: center;
                margin: 2rem 0;
                padding: 1rem;
                background: linear-gradient(90deg, rgba(0,0,102,0.1) 0%, rgba(0,0,102,0.2) 50%, rgba(0,0,102,0.1) 100%);
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .metric-card {
                background-color: white;
                padding: 1rem;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            }
        </style>
    """.replace("${primary_color}", CUSTOM_THEME['primary_color'])
       .replace("${background_color}", CUSTOM_THEME['background_color']), 
    unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def load_data():
    return permit_deny_by_ip()

@st.cache_data(show_spinner=False)
def compute_clusters(df, features, k=3):
    X = df[features].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    kmeans = KMeans(n_clusters=k, random_state=42)
    clusters = kmeans.fit_predict(X_scaled)
    return clusters, kmeans

def configure_aggrid(df):
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(enabled=True, paginationPageSize=10)
    gb.configure_side_bar()
    gb.configure_default_column(sortable=True, filterable=True)
    return gb.build()

def create_cluster_summary(df):
    summary = df.groupby('Cluster_str').agg({
        'PERMIT': ['mean', 'count'],
        'DENY': 'mean'
    }).round(2)
    return summary

def show_model():
    setup_page_config()
    apply_custom_css()
    
    st.markdown('<div class="title">🕸️ Machine Learning Dashboard</div>', unsafe_allow_html=True)
    
    # Chargement des données
    df = load_data()
    if df.empty:
        st.error("❌ Aucune donnée disponible depuis Elasticsearch.")
        return

    # Layout en colonnes
    col1, col2 = st.columns([2, 1])
    
    with col1:
        clusters, kmeans = compute_clusters(df, FEATURES)
        df["Cluster"] = clusters
        df["Cluster_str"] = "Cluster " + df["Cluster"].astype(str)
        
        # Tableau amélioré
        st.subheader("📊 Aperçu des données")
        grid_options = configure_aggrid(df)
        AgGrid(df, gridOptions=grid_options, theme='streamlit')

    with col2:
        st.subheader("📈 Résumé des clusters")
        summary = create_cluster_summary(df)
        st.dataframe(summary.style.highlight_max(axis=0))

    # Visualisations
    st.subheader("🎯 Visualisations")
    tabs = st.tabs(["Scatter Plot", "Matrice de corrélation", "Distribution"])
    
    with tabs[0]:
        fig_scatter = px.scatter(
            df, x="PERMIT", y="DENY",
            color="Cluster_str",
            hover_data=["IP_Source"] if "IP_Source" in df.columns else None,
            title="Distribution des logs par cluster",
            template="plotly_white",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig_scatter.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    # ... Ajoutez d'autres visualisations dans les autres onglets ...

if __name__ == "__main__":
    show_model()