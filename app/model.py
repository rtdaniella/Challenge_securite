import streamlit as st

def show_model():
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
        </style>
    """, unsafe_allow_html=True)
    st.markdown('<div class="title">🛡️ Machine Learning</div>', unsafe_allow_html=True)