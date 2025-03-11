import streamlit as st
from utils import permit_deny_by_ip, get_one_ip_logs
import plotly.express as px
import plotly.graph_objects as go  # Pour les graphiques temporels
import ipaddress
import pandas as pd


@st.cache_data
def filter_university_ips(df):
    """Filter IPs belonging to university networks and sort them"""
    university_networks = [
        ipaddress.ip_network("103.0.0.0/8"),
        ipaddress.ip_network("10.70.0.0/16"),
        ipaddress.ip_network("159.84.0.0/16"),
        ipaddress.ip_network("192.168.0.0/16")
    ]
    
    def is_university_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in university_networks)
        except ValueError:
            return False
    
    # Filter university IPs
    df['is_university'] = df['IP_Source'].apply(is_university_ip)
    university_df = df[df['is_university']].copy()
    
    return university_df.sort_values('PERMIT', ascending=False)



# Fonction pour récupérer les données de PERMIT et DENY par IP (mise en cache)
@st.cache_data
def get_permit_deny_by_ip():
    """
    Récupère les données de PERMIT et DENY par IP depuis une source externe.
    Les données sont mises en cache pour éviter des appels répétitifs.
    """
    try:
        return permit_deny_by_ip()
    except Exception as e:
        st.error(f"Erreur lors de la récupération des données : {e}")
        return pd.DataFrame()  # Retourne un DataFrame vide en cas d'erreur

# Fonction pour obtenir les top IPs (mise en cache)
@st.cache_data
def get_top_ips(df, column, n=5):
    """Retourne les top IPs pour une colonne donnée."""
    return df.nlargest(n, column)[['IP_Source', column]]

# Fonction pour obtenir les top ports (mise en cache)
@st.cache_data
def get_top_ports(df, n=10):
    """Retourne les top ports Well Known."""
    return df.nlargest(n, 'Port_Dest_Well_Known')[['Port_Dest_Well_Known', 'PERMIT']]

# @st.cache_data
# def get_top_ports(df, n=10):
#     """Retourne les top ports Well Known."""
#     return df.nlargest(n, 'Port_Dest_Well_Known')[['Port_Dest_Well_Known', 'PERMIT']]

# Fonction pour appliquer les filtres
def apply_filters(df, range_permit,   protocol, port_range):
    """
    Applique les filtres sélectionnés par l'utilisateur sur le DataFrame.
    """
    # Filtre par nombre de PERMIT
    filtered_df = df[(df['PERMIT'].between(range_permit[0], range_permit[1]))].copy()
    
    # Filtre par protocole
    if "TCP" in protocol and "UDP" in protocol:
        pass  # Aucun filtre nécessaire, on garde tout
    else:
        if "TCP" in protocol:
            filtered_df = filtered_df[filtered_df['PERMIT_TCP'] > 0]
        if "UDP" in protocol:
            filtered_df = filtered_df[filtered_df['PERMIT_UDP'] > 0]
    
    # Filtre par plage de ports
    if port_range == "Well Known (0-1023)":
        filtered_df = filtered_df[filtered_df['Nb_Port_Dest'].between(0, 1023)]
    elif port_range == "Registered (1024-49151)":
        filtered_df = filtered_df[filtered_df['Nb_Port_Dest'].between(1024, 49151)]
    elif port_range == "Dynamic/Private (49152-65535)":
        filtered_df = filtered_df[filtered_df['Nb_Port_Dest'].between(49152, 65535)]
    
    return filtered_df

# Fonction principale pour afficher le dashboard
def show_dashboard():
    """
    Affiche le dashboard de sécurité réseau avec des filtres, des métriques et des visualisations.
    """

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
            .kpi-card-ip {
                font-size: 20px;
                font-weight: bold;
                text-align: center;
                padding: 20px;
                background-color: #000066;
                border-radius: 15px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                margin: 10px;
                height: 150px;
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
            /* Style des onglets */
            .stTabs [role="tablist"] {
                display: flex;
                padding: 8px;
                
            }
            
            .stTabs [role="tab"] {
                color: black;
                font-weight: bold;
                
                padding: 10px 20px;
                margin: 0 10px;
                transition: background 0.3s;
            }
            
            .stTabs [role="tab"][aria-selected="true"] {
                background: #4eb151;
                color: white;
            }
            
            .stTabs [role="tab"]:hover {
                background: #46a049;
            }

            /* Amélioration des sliders et dropdowns */
            .stSlider, .stMultiSelect, .stSelectbox {
                font-size: 18px !important;
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="title">🕸️ Analyse et Visualisation des flux réseaux</div>', unsafe_allow_html=True)
    # Récupérer les données
    df = get_permit_deny_by_ip()
    
    if df.empty:
        st.warning("Aucune donnée disponible. Veuillez vérifier la source des données.")
        return
    
    #filters
    st.subheader("Filtres")
    range_permit = st.slider("✅ Nombre de PERMIT", 0, int(df['PERMIT'].max()), (0, int(df['PERMIT'].max())))
    
    col1, col2 = st.columns(2)
    with col1:
        protocol = st.multiselect(
            "Protocole", 
            ["TCP", "UDP"], 
            default=["TCP", "UDP"])
    with col2:
        port_range = st.selectbox(
            "🎯 Plage de ports", 
            [
                "Tous les ports",
                "Well Known (0-1023)",
                "Registered (1024-49151)",
                "Dynamic/Private (49152-65535)"
            ])
    
    # Appliquer les filtres
    filtered_df = apply_filters(df, range_permit, protocol, port_range)

    # Onglets pour organiser le contenu
    tab1, tab2 = st.tabs(["📉 Statistiques", "🖥️ Analyse détaillée par IP"])

    with tab1:
        st.subheader("📉 Statistiques")
        total_requests = filtered_df['COUNT'].sum()
        total_permit = filtered_df['PERMIT'].sum()
        total_deny = filtered_df['DENY'].sum()

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{total_requests:,}</div>
                <p>🌐 Total Flux</p>
            </div>
        """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{total_permit:,}</div>
                <p>✅ Flux autorisés</p>
            </div>
        """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{total_deny:,}</div>
                <p>❌ Flux rejetés</p>
            </div>
        """, unsafe_allow_html=True)

        col1, col2 , col3 = st.columns([1, 1, 1])
        with col1:            
            # Total requests
            top_total = get_top_ips(filtered_df, 'COUNT')
            fig_total = px.bar(top_total, 
                             x='IP_Source', 
                             y='COUNT',
                             title="Top 5 - Total Requêtes",
                             color_discrete_sequence=['blue'])
            st.plotly_chart(fig_total, use_container_width=True)
            

        
        with col2:
            # PERMIT requests (green)
            top_permit = get_top_ips(filtered_df, 'PERMIT')
            fig_permit = px.bar(top_permit, 
                              x='IP_Source', 
                              y='PERMIT',
                              title="Top 5 - PERMIT",
                              color_discrete_sequence=['green'])
            st.plotly_chart(fig_permit, use_container_width=True)

        with col3:
            # DENY requests (red)
            top_deny = get_top_ips(filtered_df, 'DENY')
            fig_deny = px.bar(top_deny, 
                            x='IP_Source', 
                            y='DENY',
                            title="Top 5 - DENY",
                            color_discrete_sequence=['red'])
            st.plotly_chart(fig_deny, use_container_width=True)

        col11, col22 = st.columns([1, 2])
        
        # Update the visualization code in show_edina()
        with col11:
            # Get university IPs data
            uni_df = filter_university_ips(filtered_df)
            
            # Create visualization for university IPs
            fig_uni = px.bar(
                uni_df.head(10),  # Top 10 university IPs
                x='IP_Source',
                y='PERMIT',
                title="Top 10 - IPs Université",
                color='IP_Source',
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            fig_uni.update_layout(
                showlegend=False,
                xaxis_tickangle=45,
                height=400
            )
            
            st.plotly_chart(fig_uni, use_container_width=True)
            

        
        with col22:
            # Top 10 Well Known Ports
            top_ports = get_top_ips(filtered_df, 'Port_Dest_Well_Known',n=10)
            fig_ports = px.bar(top_ports,
                             x='IP_Source',
                             y='Port_Dest_Well_Known',
                             title="Distribution des ports Well Known",
                             color_discrete_sequence=['lightblue'])
            st.plotly_chart(fig_ports, use_container_width=True)

                
                
    with tab2:
        st.subheader("🖥️ Analyse détaillée par IP")
        selected_ip = st.selectbox("🔎 Sélectionnez une IP", filtered_df["IP_Source"].unique())
        
        # Get IP data with caching
        @st.cache_data(ttl=300)
        def get_cached_ip_logs(ip):
            return get_one_ip_logs(ip)
        
        ip_data = get_cached_ip_logs(selected_ip)
        
        # Convert timestamp to datetime if not already
        ip_data['timestamp'] = pd.to_datetime(ip_data['timestamp'])
        
        # Metrics display
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
            <div class="kpi-card-ip">
                <div class="kpi-value">{ip_data.shape[0]:,}</div>
                <p>🔢 Total Requêtes</p>
            </div>
        """, unsafe_allow_html=True)
        with col2:
            permit_count = ip_data['action'].value_counts().get('PERMIT', 0)
            st.markdown(f"""
            <div class="kpi-card-ip">
                <div class="kpi-value">{permit_count:,}</div>
                <p>🔓 Total PERMIT</p>
            </div>
        """, unsafe_allow_html=True)
        with col3:
            deny_count = ip_data['action'].value_counts().get('DENY', 0)
            st.markdown(f"""
            <div class="kpi-card-ip">
                <div class="kpi-value">{deny_count:,}</div>
                <p>🔒 Total DENY</p>
            </div>
        """, unsafe_allow_html=True)
        with col4:
            rules_count = ip_data['idregle'].nunique()
            st.markdown(f"""
            <div class="kpi-card-ip">
                <div class="kpi-value">{rules_count:,}</div>
                <p>🔧 Total Règles</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Date filter and plot
        date_col, plot_col = st.columns([1, 3])
        
        with date_col:
            min_date = ip_data['timestamp'].min().date()
            max_date = ip_data['timestamp'].max().date()
            
            date_debut = st.date_input(
                "🗓️ Date de début",
                value=min_date,
                min_value=min_date,
                max_value=max_date
            )
            date_fin = st.date_input(
                "🗓️ Date de fin",
                value=max_date,
                min_value=min_date,
                max_value=max_date
            )
            
            # Show date range stats
            st.info(f"🕒 Période: {(date_fin - date_debut).days + 1} jours")
        
        with plot_col:
            # Filter data by date
            mask = (ip_data['timestamp'].dt.date >= date_debut) & \
                (ip_data['timestamp'].dt.date <= date_fin)
            filtered_ip_data = ip_data[mask]
            
            # Create time series
            daily_stats = filtered_ip_data.groupby(
                [filtered_ip_data['timestamp'].dt.date, 'action']
            ).size().unstack(fill_value=0)
            
            # Plot time series
            fig_time = go.Figure()
            
            if 'PERMIT' in daily_stats.columns:
                fig_time.add_trace(go.Scatter(
                    x=daily_stats.index,
                    y=daily_stats['PERMIT'],
                    name='PERMIT',
                    line=dict(color='green')
                ))
                
            if 'DENY' in daily_stats.columns:
                fig_time.add_trace(go.Scatter(
                    x=daily_stats.index,
                    y=daily_stats['DENY'],
                    name='DENY',
                    line=dict(color='red')
                ))
            
            fig_time.update_layout(
                title=f"📈 Activité journalière pour {selected_ip}",
                xaxis_title="Date",
                yaxis_title="Nombre d'événements",
                hovermode='x unified',
                showlegend=True,
                height=400
            )
            
            st.plotly_chart(fig_time, use_container_width=True)
        
        plot_port_destinations , plot_port_sources, plot_proto = st.columns(3)
        with plot_port_destinations:
            # Top 5 port destinations
            top_ports_dest = ip_data['portdst'].value_counts().head(5)
            fig_ports_dest = px.pie(
                top_ports_dest,
                names=top_ports_dest.index,
                values=top_ports_dest.values,
                title="Top 5 - Ports de destination"
            )
            st.plotly_chart(fig_ports_dest, use_container_width=True)
    
        with plot_port_sources:
            # Top 5 port sources
            top_ports_src = ip_data['portsrc'].value_counts().head(5)
            fig_ports_src = px.pie(
                top_ports_src,
                names=top_ports_src.index,
                values=top_ports_src.values,
                title="Top 5 - Ports sources"
            )
            st.plotly_chart(fig_ports_src, use_container_width=True)
        
        with plot_proto:
            # Protocol distribution
            proto_dist = ip_data['proto'].value_counts()
            fig_proto = px.pie(
                proto_dist,
                names=proto_dist.index,
                values=proto_dist.values,
                title="Distribution des protocoles"
            )
            st.plotly_chart(fig_proto, use_container_width=True)

