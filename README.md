**PhishGuard**

PhishGuard is a Python-based phishing detection and user protection application. It helps users identify suspicious URLs and phishing emails before interacting with them.

**Project Objective**

The main objective of PhishGuard is to help users recognise potential phishing attempts and understand what actions to take if they have already interacted with a suspicious link.

**Features**

- URL Analysis: Checks links for suspicious domains, unusual characters, URL shorteners and possible brand impersonation.
- Email Analysis: Examines email content for suspicious language, sensitive information requests, authentication failures and suspicious links.
- Risk Classification: Displays Low, Medium or High risk levels.
- Post-Click Protection: Provides guidance for users who clicked suspicious links, entered passwords, shared OTPs or downloaded files.
- Simple Interface: Easy-to-use web interface built with Streamlit.

**Technologies Used**

- Python
- Streamlit
- Regular Expressions
- URL Parsing

**How It Works**

1. The user enters a URL or email.
2. PhishGuard examines the input using predefined detection rules.
3. Suspicious indicators are identified.
4. A risk level and explanation are displayed.
5. Users can select their situation to receive relevant protection advice.

**Testing**

The application is tested using different types of URLs and email samples, including:

- Suspicious domains
- Brand impersonation attempts
- IP-based URLs
- URL shorteners
- Normal websites
- Phishing-style emails
- Legitimate email samples

**Run Locally**

*Clone the repository:*

"git clone YOUR_GITHUB_REPOSITORY_URL"

*Install dependencies:*

"pip install -r requirements.txt"

*Run the application:*

"streamlit run app.py"

**Privacy and Safety**

Do not enter real passwords, OTPs, banking information or other sensitive personal details.

PhishGuard provides rule-based assessments and does not guarantee that a URL or email is safe.

**Limitations**

- Detection is based on predefined rules and indicators.
- Some legitimate URLs may be flagged incorrectly.
- New phishing techniques may not be detected.
- The application does not replace professional security tools or independent verification.

**Future Improvements**

- Integration with trusted threat intelligence services.
- Improved domain and email authentication checks.
- Expanded phishing detection rules.
- More comprehensive security testing.
