import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from st_aggrid import AgGrid  # Pour afficher les tableaux avec AgGrid

# Importez vos fonctions depuis utils.py
from utils import permit_deny_by_ip, get_one_ip_logs

# On utilise st.cache_data pour stocker les résultats en fonction des entrées
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
def sample_for_pairplot(df, max_rows=1000000):
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
    
    st.write("### Clustering des logs par IP")
    
    # Chargement des données (mise en cache)
    df = load_data()
    
    if df.empty:
        st.error("Aucune donnée récupérée depuis Elasticsearch.")
        return
    
    st.write("Aperçu des données :")
    AgGrid(df.head())  # Affichage des données avec AgGrid

    # Colonnes numériques à utiliser pour le clustering
    features = [
        "COUNT", "PERMIT", "DENY", "PERMIT_TCP", "PERMIT_UDP", 
        "Nb_Port_Dest", "Nb_Port_Src", "Port_Dest_Well_Known", 
        "Port_Dest_Registered", "Port_Dest_Dynamic_Private"
    ]

    # Choix du nombre de clusters
    k = st.number_input("Nombre de clusters", min_value=2, max_value=10, value=3, step=1)
    
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

    st.write("Résultats du clustering :")
    AgGrid(df.head())  # Affichage des résultats avec AgGrid

    # # ----------------- Visualisation : Scatter plot (exemple) -----------------
    # st.write("### Scatter Plot (exemple) : PERMIT vs DENY")
    # fig_scatter = px.scatter(
    #     df,
    #     x="PERMIT",
    #     y="DENY",
    #     color="Cluster_str",                # On utilise la version texte pour un rendu discret
    #     hover_data=hover_cols,              # Pour afficher l'IP en tooltip
    #     title="Clustering des logs (PERMIT vs DENY)",
    #     color_discrete_sequence=px.colors.qualitative.Set2  # Palette discrète
    # )
    # st.plotly_chart(fig_scatter)

    # ----------------- Scatter matrix (équivalent pairplot) -----------------
    st.write("### Visualisation Pairplot des clusters (Scatter Matrix)")
    
    # Liste des colonnes numériques disponibles (hors colonne 'Cluster'/'Cluster_str')
    numeric_columns = [
        col for col in df.select_dtypes(include='number').columns
        if col not in ["Cluster"]
    ]
    subsetvar = st.multiselect(
        "Sélectionnez les variables pour le pairplot", 
        options=numeric_columns, 
        default=numeric_columns[:3]
    )
    
    if len(subsetvar) < 2:
        st.error("Veuillez sélectionner au moins deux variables pour le pairplot.")
    else:
        # Pour accélérer, on prend un échantillon du DataFrame pour le scatter matrix
        df_sample = sample_for_pairplot(df)
        
        # Création du scatter matrix
        fig_pair = px.scatter_matrix(
            df_sample,
            dimensions=subsetvar,
            color="Cluster_str",
            hover_data=hover_cols,
            title="Pairplot des clusters",
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        st.plotly_chart(fig_pair)

if __name__ == "__main__":
    show_model()
