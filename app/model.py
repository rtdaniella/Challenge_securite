import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from st_aggrid import AgGrid, GridOptionsBuilder
import plotly.graph_objects as go


# Importez vos fonctions depuis utils.py
from utils import permit_deny_by_ip, get_one_ip_logs

@st.cache_data(show_spinner=False)
def load_data():
    # Chargement des données depuis Elasticsearch
    return permit_deny_by_ip()

@st.cache_data(show_spinner=False)
def compute_clusters(df, features, k = 2):
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


def configure_aggrid(df):
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_pagination(enabled=True, paginationPageSize=10)
    gb.configure_side_bar()
    gb.configure_default_column(sortable=True, filterable=True)
    return gb.build()

def create_cluster_summary(df):
    summary = df.groupby('Cluster_str').agg({
        'PERMIT': ['mean'],
        'DENY':   ['mean', 'count']
    }).round(2)
    return summary

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
    
    # st.write("### Clustering des logs par IP")
    
    # Chargement des données (mise en cache)
    df = load_data()
    
    if df.empty:
        st.error("Aucune donnée récupérée depuis Elasticsearch.")
        return
    
    tab1, tab2 = st.tabs(["📉 Clustering", "🖥️ Analyse détaillée"])


    # Colonnes numériques à utiliser pour le clustering
    features = [
        "COUNT", "PERMIT", "DENY", "PERMIT_TCP", "PERMIT_UDP", 
        "Nb_Port_Dest", "Nb_Port_Src", "Port_Dest_Well_Known", 
        "Port_Dest_Registered", "Port_Dest_Dynamic_Private"
    ]

    # Choix du nombre de clusters
    # k = st.number_input("Nombre de clusters", min_value=2, max_value=10, value=3, step=1)
    
    # Calcul des clusters (mise en cache)
    clusters, _ = compute_clusters(df, features)
    df["Cluster"] = clusters  # Ajout des labels de clusters (entiers)

    # Créer une version "texte" du cluster pour un affichage catégoriel
    df["Cluster_str"] = df["Cluster"].apply(lambda x: f"Cluster {x}")

    # Vérifier l'existence de la colonne "IP_Source" pour les tooltips
    if "IP_Source" not in df.columns:
        st.warning("La colonne 'IP_Source' n'existe pas. Les IP ne seront pas affichées dans les tooltips.")
        hover_cols = []
    else:
        hover_cols = ["IP_Source"]  # Liste des colonnes à afficher en tooltip

    # Mapper les clusters en "Attaque" et "Utilisateur normal"
    df["Cluster_str"] = df["Cluster"].map({
        0: "Utilisateur normal",  # Cluster 0 devient "Utilisateur normal"
        1: "Attaque"              # Cluster 1 devient "Attaque"
    })

    with tab1:
        # Affichage des résultats du clustering
        # st.write("Résultats du clustering :")
        # AgGrid(df.head())  # Affichage des résultats avec AgGrid
        plot_col, explication = st.columns([3, 1])

        
        with plot_col:
            # ----------------- Visualisation : Scatter plot (exemple) -----------------
            # st.write("###Clustering des logs  PERMIT vs DENY")
            fig_scatter = px.scatter(
                df,
                x="PERMIT",
                y="DENY",
                color="Cluster_str",                # On utilise la version texte pour un rendu discret
                hover_data=hover_cols,              # Pour afficher l'IP en tooltip
                title="Clustering des logs (PERMIT vs DENY)",
                color_discrete_map={
                    "Attaque": "red",               # "Attaque" en rouge
                    "Utilisateur normal": "green"   # "Utilisateur normal" en vert
                },
                size_max=25,                        # Taille maximale des points
                size="COUNT",                       # Utilisez une colonne numérique pour la taille des points (ex: "COUNT")
            )
            st.plotly_chart(fig_scatter)

        with explication:
            st.subheader("📈 Résumé des clusters")
            summary = create_cluster_summary(df)
            st.dataframe(summary.style.highlight_max(axis=0))



            # Calculer le pourcentage de logs pour chaque cluster
            cluster_percentage = df['Cluster_str'].value_counts(normalize=True) * 100
            cluster_percentage = cluster_percentage.reset_index()
            cluster_percentage.columns = ['Cluster_str', 'Pourcentage']

            # Créer le graphique en camembert
            fig_pie = px.pie(
                cluster_percentage,
                names='Cluster_str',  # Noms des clusters
                values='Pourcentage',  # Pourcentages
                title="Répartition par cluster",
                color='Cluster_str',   # Couleur par cluster
                color_discrete_map={
                    "Attaque": "red",               # "Attaque" en rouge
                    "Utilisateur normal": "green"   # "Utilisateur normal" en vert
                },
                labels={'Cluster_str': 'Cluster', 'Pourcentage': 'Pourcentage des logs'}
            )
            st.plotly_chart(fig_pie)


    with tab2:
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
 
