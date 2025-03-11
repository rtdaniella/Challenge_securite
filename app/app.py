import streamlit as st
from streamlit_option_menu import option_menu

st.set_page_config(layout="wide")

with st.sidebar:

    st.image("assets/logo.png", use_container_width=True)

    selected = option_menu(
        "", 
        ["📈 Dashboard", "📄 Données", "🛡️ Détection d'anomalies"],
        icons=["📈", "📄", "🛡️"],
        menu_icon="none",
    )

if selected == "📈 Dashboard":
    import dashboard
    dashboard.show_dashboard()
elif selected == "📄 Données":
    import explore_data
    explore_data.show_data()
elif selected == "🛡️ Détection d'anomalies":
    import model
    model.show_model()

# elif selected == "Analyse":
#     import analyse
#     analyse.show_analyse()
# elif selected == "📈 Analyse réseau":
#     import linhnhi
#     linhnhi.show_linhnhi()
# elif selected == "Edina":
#     import edina
#     edina.show_edina()

