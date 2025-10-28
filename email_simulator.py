import streamlit as st
import re
import datetime

# --- Configuration ---
st.set_page_config(
    page_title="Email Security Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Monitoring Engine (The "Server" Logic) ---

def check_financials(body_text):
    """Finds currency symbols followed by numbers or large standalone numbers."""
    # Pattern for currency: $1,000.00, €500, 10,000
    pattern = r"([$€£]\s?[\d,]+(?:\.\d{2})?|(?<!\w)[\d,]{4,}(?!\w))"
    if re.search(pattern, body_text):
        return "Financial Details Detected"
    return None

def check_phone_numbers(body_text):
    """Finds common US-style phone number formats."""
    # Pattern for (123) 456-7890, 123-456-7890, 123.456.7890, etc.
    pattern = r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
    if re.search(pattern, body_text):
        return "Phone Number Detected"
    return None

def check_numbers_in_words(body_text):
    """Finds common number words."""
    number_words = [
        "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "hundred", "thousand", "million", "billion"
    ]
    body_lower = body_text.lower()
    if any(word in body_lower for word in number_words):
        return "Numbers in Words Detected"
    return None

def check_image_attachment(file):
    """Checks if a file is an image."""
    if file.type.startswith("image/"):
        return "Image Attachment Detected"
    return None

def check_attachment_size(file, max_size_mb):
    """Checks if a file exceeds the size limit."""
    max_size_bytes = max_size_mb * 1024 * 1024
    if file.size > max_size_bytes:
        return f"Attachment Size Exceeds Limit ({max_size_mb}MB)"
    return None

# --- Session State Initialization ---
# This holds our "database" of logged emails
if "email_log" not in st.session_state:
    st.session_state.email_log = []

# --- Sidebar (Configuration) ---
st.sidebar.title("🛡️ Server Configuration")
st.sidebar.markdown("Set the monitoring rules and alert settings.")

manager_email = st.sidebar.text_input(
    "Manager's Alert Email", 
    "manager@company.com"
)
max_size = st.sidebar.number_input(
    "Max Attachment Size (MB)", 
    min_value=1, 
    value=10
)

st.sidebar.subheader("Active Monitoring Rules")
active_rules = st.sidebar.multiselect(
    "Select rules to enforce:",
    ["Financials", "Phone Numbers", "Numbers in Words", "Image Files", "Attachment Size"],
    default=["Financials", "Phone Numbers", "Image Files", "Attachment Size"]
)

# --- Main Application UI ---
st.title("Email Security Simulator Server")
st.markdown("This tool simulates an email server that monitors *metadata* for policy violations but **cannot** read the email content in its log.")

# Columns for layout
col1, col2 = st.columns([1, 1.5], gap="large")

# --- 1. Email Prepare (Client Simulator) ---
with col1:
    st.header("1. Email Prepare (Simulator)")
    st.markdown("Compose a test email to send through the 'server'.")

    with st.form("email_form", clear_on_submit=True):
        from_email = st.text_input("From:", "employee@company.com")
        to_email = st.text_input("To:", "external.vendor@gmail.com")
        subject = st.text_input("Subject:", "Invoice for Payment")
        body = st.text_area(
            "Body:", 
            "Hi,\n\nPlease find the attached invoice for $10,500. \n\nMy number is (555) 123-4567 if you have questions.\n\nThanks.",
            height=200
        )
        attachments = st.file_uploader(
            "Attachments:", 
            accept_multiple_files=True
        )
        
        submitted = st.form_submit_button("Simulate Send Email")

    if submitted:
        flags = []
        attachment_details = []
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- Run Monitoring Engine ---
        
        if "Financials" in active_rules:
            flag = check_financials(body)
            if flag: flags.append(flag)
        
        if "Phone Numbers" in active_rules:
            flag = check_phone_numbers(body)
            if flag: flags.append(flag)

        if "Numbers in Words" in active_rules:
            flag = check_numbers_in_words(body)
            if flag: flags.append(flag)

        # Process attachments
        if attachments:
            for file in attachments:
                size_mb = file.size / (1024 * 1024)
                attachment_details.append(f"{file.name} ({size_mb:.2f} MB)")
                
                if "Image Files" in active_rules:
                    flag = check_image_attachment(file)
                    if flag: flags.append(flag)
                
                if "Attachment Size" in active_rules:
                    flag = check_attachment_size(file, max_size)
                    if flag: flags.append(flag)
        
        # Remove duplicate flags
        flags = list(set(flags))

        # --- Create Log Entry (WITHOUT BODY) ---
        log_entry = {
            "id": len(st.session_state.email_log) + 1,
            "timestamp": timestamp,
            "from": from_email,
            "to": to_email,
            "subject": subject,
            "flags": flags,
            "attachments": attachment_details,
            "manager_alert": f"Alert sent to {manager_email}" if flags else "No alert sent."
        }
        
        # Add to log (newest first)
        st.session_state.email_log.insert(0, log_entry)
        
        st.success("Email 'sent' and processed by simulator! Check the log.  MOCK")


# --- 2. Monitoring Log (Server View / "Email Read" Section) ---
with col2:
    st.header("2. Monitoring Log (Server View)")
    st.markdown(
        "This log shows email *metadata* and *flags* only. **Email content is not stored or readable here.**"
    )

    if not st.session_state.email_log:
        st.info("No emails processed yet. Send an email from the simulator.")
    
    # Display each log entry
    for entry in st.session_state.email_log:
        is_flagged = len(entry["flags"]) > 0
        
        if is_flagged:
            icon = "🚩"
            status = "[RED FLAG]"
        else:
            icon = "✅"
            status = "[CLEARED]"
            
        expander_title = f"{icon} {status} ({entry['timestamp']}) | From: {entry['from']} | Subject: {entry['subject']}"
        
        with st.expander(expander_title):
            st.markdown(f"**From:** `{entry['from']}`")
            st.markdown(f"**To:** `{entry['to']}`")
            st.markdown(f"**Subject:** `{entry['subject']}`")
            st.markdown(
                f"**Attachments:** `{', '.join(entry['attachments']) if entry['attachments'] else 'None'}`"
            )
            
            st.subheader("Monitoring Results:")
            if is_flagged:
                for flag in entry["flags"]:
                    st.warning(f"**Flag:** {flag}")
                st.error(f"**Action Taken:** {entry['manager_alert']}")
            else:
                st.success("No flags detected.")
                st.info(f"**Action Taken:** {entry['manager_alert']}")
