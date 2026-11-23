import os

import streamlit as st

from classifier import analyze


st.set_page_config(page_title="PhishClass", page_icon="🔎")
st.title("Классификатор фишинга")
st.write("Вставьте текст подозрительного письма, URL или оба сразу.")

api_key = os.getenv("OPENAI_API_KEY", "").strip()
with st.form("analysis"):
    email = st.text_area("Текст письма", height=180, max_chars=12_000)
    url = st.text_input("URL", max_chars=2_048)
    if api_key:
        st.caption("При анализе введённые данные передаются в OpenAI.")
    submitted = st.form_submit_button("Проанализировать", type="primary")

if submitted:
    st.session_state.pop("result", None)
    if email.strip() or url.strip():
        with st.spinner("Анализируем признаки фишинга…"):
            st.session_state.result = analyze(email.strip(), url.strip(), api_key)
        st.session_state.revision = st.session_state.get("revision", 0) + 1
    else:
        st.warning("Введите текст письма или URL.")

if "result" in st.session_state:
    techniques, source = st.session_state.result
    st.subheader("Возможные техники")
    st.caption(source)
    if not techniques:
        st.info("По введённым данным мало признаков для определения техники.")
    for technique in techniques:
        st.markdown(f"**{technique.name}**")
        st.write(technique.risk)

    st.subheader("Чеклист реагирования")
    steps = [
        "Воздержитесь от перехода по ссылкам и открытия вложений.",
        "Сохраните исходное письмо или URL и передайте в службу безопасности.",
        *(technique.action for technique in techniques),
    ]
    for index, step in enumerate(steps):
        st.checkbox(step, key=f"step_{st.session_state.revision}_{index}")
