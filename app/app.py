import streamlit as st
from streamlit_option_menu import option_menu

st.set_page_config(layout="wide")

with st.sidebar:

    #st.image("assets/images/logo.png", use_container_width=True)

    selected = option_menu(
        "", 
        ["Accueil", "Analyse", "Machine Learning", "Daniella", "Linh-Nhi", "Edina"],
        icons=["house", "graph-up", "bar-chart-steps", "bar-chart-steps", "bar-chart-steps", "bar-chart-steps"],
        menu_icon="none",
    )

if selected == "Accueil":
    import accueil
    accueil.show_accueil()
elif selected == "Analyse":
    import analyse
    analyse.show_analyse()
elif selected == "Model":
    import model
    model.show_model()
elif selected == "Daniella":
    import daniella
    daniella.show_daniella()
elif selected == "Linh-Nhi":
    import linhnhi
    linhnhi.show_linhnhi()
elif selected == "Edina":
    import edina
    edina.show_edina()