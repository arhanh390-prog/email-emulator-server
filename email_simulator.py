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
# Each function returns a string (the flag) or None

def check_financials(body_text):
    """Finds currency symbols followed by numbers or large standalone numbers."""
    pattern = r"([$€£]\s?[\d,]+(?:\.\d{2})?|(?<!\w)[\d,]{4,}(?!\w))"
    if re.search(pattern, body_text):
        return "Financial Details Detected"
    return None

def check_phone_numbers(body_text):
    """Finds common US-style phone number formats."""
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

def check_credit_cards(body_text):
    """Finds common credit card number patterns."""
    # Simple regex for 16-digit numbers in groups of 4
    pattern = r"\b(?:\d[ -]?){15}\d\b"
    if re.search(pattern, body_text):
        return "PII: Credit Card Number Detected"
    return None

def check_ssn(body_text):
    """Finds SSN patterns."""
    pattern = r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b"
    if re.search(pattern, body_text):
        return "PII: Social Security Number (SSN) Detected"
    return None

def check_custom_keywords(body_text, keywords):
    """Finds custom keywords from the sidebar list."""
    if not keywords:
        return None
    
    body_lower = body_text.lower()
    for keyword in keywords:
        if keyword.lower() in body_lower:
            return f"Sensitive Keyword Detected: '{keyword}'"
    return None

def check_links(body_text, blocked_domains):
    """Finds all links and checks them against the blacklist."""
    links = re.findall(r"(https?://[^\s]+)", body_text)
    if not links:
        return None
    
    for link in links:
        for domain in blocked_domains:
            if domain in link:
                return f"High-Risk Link Detected (Blocked Domain): {link}"
    
    # If links are found but none are blocked, just flag that links exist
    return "Links Detected in Body"

def check_urgency(body_text):
    """Looks for common phishing 'urgency' keywords."""
    urgency_words = [
        "urgent", "asap", "immediate action required", "password expired", 
        "account suspended", "verify your account", "action required"
    ]
    body_lower = body_text.lower()
    if any(word in body_lower for word in urgency_words):
        return "Suspicious Phishing Language (Urgency) Detected"
    return None

def check_domains(to_email, trusted_domains, blocked_domains):
    """Checks the 'To:' field against domain whitelists/blacklists."""
    recipient_domain = to_email.split('@')[-1]
    
    if recipient_domain in blocked_domains:
        return f"Outbound to Blocked Domain: {recipient_domain}"
    
    if trusted_domains and recipient_domain not in trusted_domains:
        return f"Outbound to Non-Trusted Domain: {recipient_domain}"
    
    return None

def check_image_attachment(file):
    """Checks if a file is an image."""
    if file.type.startswith("image/"):
        return "Image Attachment Detected"
    return None

def check_banned_file_types(file, banned_types):
    """Checks file extension against the banned list."""
    if not banned_types:
        return None
    
    file_ext = f".{file.name.split('.')[-1].lower()}"
    if file_ext in banned_types:
        return f"Banned File Type Detected: {file_ext}"
    return None

def check_attachment_size(file, max_size_mb):
    """Checks if a file exceeds the size limit."""
    max_size_bytes = max_size_mb * 1024 * 1024
    if file.size > max_size_bytes:
        return f"Attachment Size Exceeds Limit ({max_size_mb}MB)"
    return None

# --- Session State Initialization & Callbacks ---

if "email_log" not in st.session_state:
    st.session_state.email_log = []

def resolve_alert(entry_id):
    """Callback to mark an alert as resolved."""
    for entry in st.session_state.email_log:
        if entry["id"] == entry_id:
            entry["resolved"] = True
            break

def clear_log():
    """Callback to clear the entire log."""
    st.session_state.email_log = []

# --- Sidebar (Configuration) ---
st.sidebar.title("🛡️ Server Configuration")
st.sidebar.markdown("Set the monitoring rules and alert settings.")

manager_email = st.sidebar.text_input(
    "Manager's Alert Email", 
    "manager@company.com"
)

st.sidebar.subheader("Global Rules")
max_size = st.sidebar.number_input(
    "Max Attachment Size (MB)", 
    min_value=1, 
    value=10
)

st.sidebar.subheader("Active Monitoring Rules")
active_rules = st.sidebar.multiselect(
    "Select rules to enforce:",
    [
        "Financials", "Phone Numbers", "Numbers in Words", "PII: Credit Cards", "PII: SSNs",
        "Image Files", "Attachment Size", "Custom Keywords", "Domain Blocking",
        "Check for Links", "Phishing Language"
    ],
    default=[
        "Financials", "Phone Numbers", "Image Files", "Attachment Size", 
        "PII: Credit Cards", "Domain Blocking", "Phishing Language"
    ]
)

st.sidebar.subheader("Rule Configuration")
custom_keywords_input = st.sidebar.text_area(
    "Custom Keywords (one per line)", 
    "Project Phoenix\nConfidential\nInternal Use Only"
)
custom_keywords = [k.strip() for k in custom_keywords_input.split('\n') if k.strip()]

trusted_domains_input = st.sidebar.text_area(
    "Trusted Domains (one per line)", 
    "company.com\ntrusted-partner.com"
)
trusted_domains = [d.strip() for d in trusted_domains_input.split('\n') if d.strip()]

blocked_domains_input = st.sidebar.text_area(
    "Blocked Domains (one per line)", 
    "competitor.com\nsuspicious-site.net\ngmail.com"
)
blocked_domains = [d.strip() for d in blocked_domains_input.split('\n') if d.strip()]

banned_file_types_input = st.sidebar.text_area(
    "Banned File Types (e.g., .exe, .zip)", 
    ".exe\n.zip\n.vbs\n.js"
)
banned_file_types = [t.strip().lower() for t in banned_file_types_input.split('\n') if t.strip()]

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
            "Hi,\n\nPlease find the attached invoice for $10,500. \n\nMy SSN is 123-45-6789 for your records. "
            "My number is (555) 123-4567 if you have questions.\n\n"
            "PS: This is an URGENT request, please action immediately.\n\nThanks.",
            height=250
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
        rule_functions = {
            "Financials": lambda: check_financials(body),
            "Phone Numbers": lambda: check_phone_numbers(body),
            "Numbers in Words": lambda: check_numbers_in_words(body),
            "PII: Credit Cards": lambda: check_credit_cards(body),
            "PII: SSNs": lambda: check_ssn(body),
            "Custom Keywords": lambda: check_custom_keywords(body, custom_keywords),
            "Check for Links": lambda: check_links(body, blocked_domains),
            "Phishing Language": lambda: check_urgency(body),
            "Domain Blocking": lambda: check_domains(to_email, trusted_domains, blocked_domains)
        }
        
        for rule_name, rule_func in rule_functions.items():
            if rule_name in active_rules:
                flag = rule_func()
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
                
                if banned_file_types:
                    flag = check_banned_file_types(file, banned_file_types)
                    if flag: flags.append(flag)
        
        # Remove duplicate flags
        flags = sorted(list(set(flags)))

        # --- Create Log Entry (WITHOUT BODY) ---
        log_entry = {
            "id": len(st.session_state.email_log) + 1,
            "timestamp": timestamp,
            "from": from_email,
            "to": to_email,
            "subject": subject,
            "flags": flags,
            "attachments": attachment_details,
            "manager_alert": f"Alert sent to {manager_email}" if flags else "No alert sent.",
            "resolved": False
        }
        
        st.session_state.email_log.insert(0, log_entry)
        st.success("Email 'sent' and processed by simulator! Check the log.")


# --- 2. Monitoring Log (Server View / "Email Read" Section) ---
with col2:
    st.header("2. Monitoring Log (Server View)")
    st.markdown(
        "This log shows email *metadata* and *flags* only. **Email content is not stored or readable here.**"
    )

    # --- Dashboard Metrics ---
    total_processed = len(st.session_state.email_log)
    total_flags = sum(1 for e in st.session_state.email_log if e["flags"] and not e["resolved"])
    
    m1, m2 = st.columns(2)
    m1.metric("Total Emails Processed", total_processed)
    m2.metric("Active Red Flags", total_flags)

    # --- Log Filtering and Controls ---
    st.subheader("Log Controls")
    f1, f2, f3 = st.columns([1.5, 1.5, 1])
    
    filter_status = f1.selectbox(
        "Filter by Status:", 
        ["All", "Active Red Flags", "Resolved Flags", "Cleared (No Flags)"]
    )
    filter_text = f2.text_input("Filter by Sender or Recipient:")
    
    with f3:
        st.markdown("") # for vertical alignment
        st.markdown("")
        clear_button = st.button("Clear Entire Log", on_click=clear_log, use_container_width=True)

    st.markdown("---")

    # --- Display Log ---
    if not st.session_state.email_log:
        st.info("No emails processed yet. Send an email from the simulator.")
    
    # Apply filters
    filtered_log = st.session_state.email_log
    
    if filter_status == "Active Red Flags":
        filtered_log = [e for e in filtered_log if e["flags"] and not e["resolved"]]
    elif filter_status == "Resolved Flags":
        filtered_log = [e for e in filtered_log if e["resolved"]]
    elif filter_status == "Cleared (No Flags)":
        filtered_log = [e for e in filtered_log if not e["flags"]]
        
    if filter_text:
        filter_text_lower = filter_text.lower()
        filtered_log = [
            e for e in filtered_log 
            if filter_text_lower in e["from"].lower() or filter_text_lower in e["to"].lower()
        ]

    if not filtered_log and st.session_state.email_log:
        st.warning("No log entries match your filters.")

    # Display each log entry
    for entry in filtered_log:
        is_flagged = bool(entry["flags"])
        is_resolved = entry["resolved"]
        
        if is_flagged and not is_resolved:
            icon = "🚩"
            status = "[RED FLAG]"
        elif is_flagged and is_resolved:
            icon = "⚠️"
            status = "[FLAG RESOLVED]"
        else:
            icon = "✅"
            status = "[CLEARED]"
            
        expander_title = f"{icon} {status} ({entry['timestamp']}) | From: {entry['from']} | To: {entry['to']}"
        
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
                
                if not is_resolved:
                    st.error(f"**Action Taken:** {entry['manager_alert']}")
                    st.button(
                        "Mark as Resolved", 
                        key=f"resolve_{entry['id']}", 
                        on_click=resolve_alert, 
                        args=(entry['id'],)
                    )
                else:
                    st.info(f"This alert was marked as resolved.")
            else:
                st.success("No flags detected.")
                st.info(f"**Action Taken:** {entry['manager_alert']}")

