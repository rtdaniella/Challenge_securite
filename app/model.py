import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from st_aggrid import AgGrid, GridOptionsBuilder  # Ajout de GridOptionsBuilder

# Importez vos fonctions depuis utils.py
from utils import permit_deny_by_ip, get_one_ip_logs

@st.cache_data(show_spinner=False)
def load_data():
    # Chargement des données depuis Elasticsearch
    return permit_deny_by_ip()

@st.cache_data(show_spinner=False)
def compute_clusters(df, features, k):
    X = df[features].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    kmeans = KMeans(n_clusters=k, random_state=42)
    clusters = kmeans.fit_predict(X_scaled)
    return clusters, kmeans

@st.cache_data(show_spinner=False)
def sample_for_pairplot(df, max_rows=800000):
    # Si le DataFrame est grand, on en prend un échantillon pour accélérer l'affichage
    if len(df) > max_rows:
        return df.sample(max_rows, random_state=42)
    return df

def show_model():
    # Style CSS pour l'onglet
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
        </style>
    """, unsafe_allow_html=True)
    st.markdown('<div class="title">🕸️Machine Learning</div>', unsafe_allow_html=True)

    # Chargement des données (mise en cache)
    df = load_data()
    
    if df.empty:
        st.error("Aucune donnée récupérée depuis Elasticsearch.")
        return
    # Utilisation d'AgGrid avec une configuration avancée
    st.subheader("📋 Tableau des Logs")

    # Colonnes numériques à utiliser pour le clustering
    features = [
        "COUNT", "PERMIT", "DENY", "PERMIT_TCP", "PERMIT_UDP", 
        "Nb_Port_Dest", "Nb_Port_Src", "Port_Dest_Well_Known", 
        "Port_Dest_Registered", "Port_Dest_Dynamic_Private"
    ]

    # Choix du nombre de clusters
    k = st.number_input("Nombre de clusters", min_value=2, max_value=10, value=2, step=1)
    
    # Calcul des clusters (mise en cache)
    clusters, _ = compute_clusters(df, features, k)
    df["Cluster"] = clusters  # Ajout des labels de clusters (entiers)

    # Créer une version "texte" du cluster pour un affichage catégoriel
    df["Cluster_str"] = df["Cluster"].apply(lambda x: f"Cluster {x}")

    # Vérifier l'existence de la colonne "IP_Source" pour les tooltips
    if "IP_Source" not in df.columns:
        st.warning("La colonne 'IP_Source' n'existe pas. Les IP ne seront pas affichées dans les tooltips.")
        hover_cols = []
    else:
        hover_cols = ["IP_Source"]  # Liste des colonnes à afficher en tooltip

    # AgGrid avancée pour afficher les résultats
    df_result = df.drop("Cluster_str", axis=1)
    gb2 = GridOptionsBuilder.from_dataframe(df_result)
    gb2.configure_pagination(enabled=True, paginationPageSize=20)
    gb2.configure_default_column(filterable=True, sortable=True, resizable=True)
    grid_options2 = gb2.build()
    AgGrid(df_result, gridOptions=grid_options2, enable_enterprise_modules=True)

    # ----------------- Scatter matrix (équivalent pairplot) -----------------
    st.write("### Visualisation Pairplot des clusters")
    
    # Liste des colonnes numériques disponibles (hors colonne 'Cluster'/'Cluster_str')
    numeric_columns = [
        col for col in df.select_dtypes(include='number').columns
        if col not in ["Cluster"]
    ]
    subsetvar = st.multiselect(
        "Sélectionnez les variables pour le pairplot", 
        options=numeric_columns, 
        default=numeric_columns[:4]
    )
    
    if len(subsetvar) < 2:
        st.error("Veuillez sélectionner au moins deux variables pour le pairplot.")
    else:
        # Pour accélérer, on prend un échantillon du DataFrame pour le scatter matrix
        df_sample = sample_for_pairplot(df)
        
        fig_pair = px.scatter_matrix(
            df_sample,
            dimensions=subsetvar,
            color="Cluster_str",
            hover_data=hover_cols,
            title="Pairplot des clusters",
            color_discrete_sequence=px.colors.qualitative.Set2
        )

        # Ajuster la taille globale du graphique
        fig_pair.update_layout(
            width=900,
            height=900,
            margin=dict(l=40, r=40, b=40, t=40),
        )

        # Taille et transparence des points
        fig_pair.update_traces(marker=dict(size=8, opacity=0.9))

        # Activer la grille dans chaque sous-graphique (axes X et Y)
        fig_pair.update_xaxes(showgrid=True, gridwidth=1, gridcolor='LightGray')
        fig_pair.update_yaxes(showgrid=True, gridwidth=1, gridcolor='LightGray')

        # Afficher le graphique dans Streamlit
        st.plotly_chart(fig_pair)



if __name__ == "__main__":
    show_model()
