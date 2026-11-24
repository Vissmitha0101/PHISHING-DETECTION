import streamlit as st
from detector import analyze_email, analyze_url
from advice import ADVICE, get_advice

st.set_page_config(page_title="PhishGuard", layout="centered")

st.title(" PhishGuard")
st.caption("Phishing detection and user protection tool. Detects suspicious links, Identifies Phishing emails. Make safer digital decisions!!")

# Privacy note
st.info(
    " **Privacy**: Avoid entering real passwords, OTPs, "
    "bank details, or other sensitive personal information. "
    "Submitted content is processed for analysis by this application."
)

# Keep results between Streamlit reruns
if "result" not in st.session_state:
    st.session_state.result = None

mode = st.radio(
    "What would you like to check?",
    ["Suspicious Link", "Email Content"],
    horizontal=True
)

if mode == "Suspicious Link":
    url_input = st.text_input(
        "Paste the link to check",
        placeholder="https://example.com/login"
    )

    if st.button("Check Link", type="primary"):
        if not url_input.strip():
            st.warning("Please enter a link.")
        else:
            st.session_state.result = analyze_url(url_input)

elif mode == "Email Content":
    email_input = st.text_area(
        "Paste the email content (including headers if possible)",
        height=220,
        placeholder="Paste the email body, or forward the full email source..."
    )

    if st.button("Check Email", type="primary"):
        if not email_input.strip():
            st.warning("Please enter email content.")
        elif len(email_input) > 50000:
            st.warning("The content is too long, please paste the core part (within 50,000 characters).")
        else:
            st.session_state.result = analyze_email(email_input)

# Display results
result = st.session_state.result

if result:
    risk = result["risk"]
    color = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}[risk]

    st.subheader(f"{color} Risk Level: {risk}")

    if risk == "Low":
        st.caption(
            "⚠️ No obvious suspicious features were found, "
            "but this does not mean the link/email is 100% safe. "
            "Please stay cautious."
        )

    st.markdown("### Findings")

    for reason in result["reasons"]:
        st.markdown(f"- {reason}")

    # Display links found in email
    if "links" in result and result["links"]:
        with st.expander("Links detected in the email"):
            for link in result["links"]:
                st.markdown(
                    f"**{link['risk']}** — `{link['url'][:80]}`"
                )

    st.divider()

    # Post-click advice
    st.subheader("⚠️ What if you have already clicked?")

    scenario = st.selectbox(
        "Please select your situation:",
        options=list(ADVICE.keys()),
        format_func=lambda x: ADVICE[x]["title"]
    )

    advice = get_advice(scenario)

    st.markdown(f"**{advice['title']}**")

    for i, step in enumerate(advice["steps"], 1):
        st.markdown(f"{i}. {step}")

    st.caption(f"Source: {advice['source']}")
