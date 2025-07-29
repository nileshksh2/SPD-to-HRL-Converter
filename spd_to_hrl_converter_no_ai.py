import streamlit as st
import pandas as pd
import PyPDF
import io
import re
from datetime import datetime
from typing import List, Dict, Tuple
import json

# Page configuration
st.set_page_config(
    page_title="SPD to HRL Converter (No AI)",
    page_icon="📄",
    layout="wide"
)

# Initialize session state
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []
if 'extracted_data' not in st.session_state:
    st.session_state.extracted_data = pd.DataFrame()
if 'hrl_syntax' not in st.session_state:
    st.session_state.hrl_syntax = ""

# Common benefit categories to search for
BENEFIT_CATEGORIES = [
    "Preventive Care",
    "Primary Care",
    "Office Visit",
    "Specialist Visit",
    "Emergency Room",
    "Emergency Services",
    "Urgent Care",
    "Hospital Inpatient",
    "Hospital Outpatient",
    "Surgery",
    "Maternity",
    "Mental Health",
    "Behavioral Health",
    "Substance Abuse",
    "Physical Therapy",
    "Occupational Therapy",
    "Speech Therapy",
    "Rehabilitation",
    "Laboratory",
    "Lab Services",
    "X-ray",
    "Imaging",
    "MRI",
    "CT Scan",
    "Prescription Drugs",
    "Generic Drugs",
    "Brand Drugs",
    "Specialty Drugs",
    "Dental",
    "Vision",
    "Hearing",
    "Durable Medical Equipment",
    "DME",
    "Home Health",
    "Skilled Nursing",
    "Hospice",
    "Ambulance",
    "Chiropractic"
]

# Common coverage patterns
COVERAGE_PATTERNS = {
    'copay': r'\$\s*(\d+(?:\.\d{2})?)\s*(?:copay|co-pay|per visit)',
    'coinsurance': r'(\d+)\s*%\s*(?:coinsurance|covered|after deductible)',
    'deductible': r'(?:after deductible|deductible applies|subject to deductible)',
    'no_charge': r'(?:no charge|covered in full|100%|0%|waived)',
    'not_covered': r'(?:not covered|0% covered|excluded)',
    'dollar_limit': r'\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(?:maximum|max|limit)',
    'visit_limit': r'(\d+)\s*(?:visits?|days?|treatments?)\s*(?:per year|annually|maximum)'
}

def extract_text_from_pdf(file) -> str:
    """Extract text content from PDF file"""
    try:
        pdf_reader = pypdf.PdfReader(file)
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        st.error(f"Error reading PDF {file.name}: {str(e)}")
        return ""

def clean_text(text: str) -> str:
    """Clean and normalize text"""
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters but keep $, %, and numbers
    text = re.sub(r'[^\w\s\$%\-\.,]', ' ', text)
    return text.strip()

def extract_coverage_info(text_segment: str) -> Dict[str, str]:
    """Extract coverage information from a text segment"""
    coverage = {
        'type': 'unknown',
        'value': '',
        'details': ''
    }
    
    text_lower = text_segment.lower()
    
    # Check for copay
    copay_match = re.search(COVERAGE_PATTERNS['copay'], text_segment, re.IGNORECASE)
    if copay_match:
        coverage['type'] = 'copay'
        coverage['value'] = f"${copay_match.group(1)}"
        coverage['details'] = 'copay'
        return coverage
    
    # Check for no charge
    if re.search(COVERAGE_PATTERNS['no_charge'], text_lower):
        coverage['type'] = 'coinsurance'
        coverage['value'] = '100%'
        coverage['details'] = 'covered in full'
        return coverage
    
    # Check for not covered
    if re.search(COVERAGE_PATTERNS['not_covered'], text_lower):
        coverage['type'] = 'not_covered'
        coverage['value'] = '0%'
        coverage['details'] = 'not covered'
        return coverage
    
    # Check for coinsurance
    coinsurance_match = re.search(COVERAGE_PATTERNS['coinsurance'], text_segment, re.IGNORECASE)
    if coinsurance_match:
        coverage['type'] = 'coinsurance'
        coverage['value'] = f"{coinsurance_match.group(1)}%"
        if re.search(COVERAGE_PATTERNS['deductible'], text_lower):
            coverage['details'] = 'after deductible'
        else:
            coverage['details'] = 'coinsurance'
        return coverage
    
    return coverage

def extract_benefits_from_text(text: str, filename: str) -> List[Dict]:
    """Extract benefit information using pattern matching"""
    benefits = []
    text_lower = text.lower()
    lines = text.split('\n')
    
    # Search for each benefit category
    for category in BENEFIT_CATEGORIES:
        category_lower = category.lower()
        
        # Find all occurrences of the category
        for i, line in enumerate(lines):
            if category_lower in line.lower():
                # Extract surrounding context (5 lines before and after)
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                context = ' '.join(lines[start:end])
                
                # Look for in-network and out-of-network patterns
                in_network_text = ""
                out_network_text = ""
                
                # Common patterns for network distinction
                if 'in-network' in context.lower() or 'in network' in context.lower():
                    # Split by network type
                    parts = re.split(r'out-of-network|out of network|non-network', context, flags=re.IGNORECASE)
                    if len(parts) > 0:
                        in_network_text = parts[0]
                    if len(parts) > 1:
                        out_network_text = parts[1]
                else:
                    # If no clear network distinction, use the whole context
                    in_network_text = context
                    out_network_text = context
                
                # Extract coverage for in-network
                in_coverage = extract_coverage_info(in_network_text)
                
                # Extract coverage for out-of-network
                out_coverage = extract_coverage_info(out_network_text)
                
                # Create benefit entry if we found meaningful coverage info
                if in_coverage['value'] or out_coverage['value']:
                    benefit = {
                        'service_category': category,
                        'in_network_coverage': f"{in_coverage['value']} {in_coverage['details']}".strip(),
                        'out_of_network_coverage': f"{out_coverage['value']} {out_coverage['details']}".strip(),
                        'spd_file': filename
                    }
                    
                    # Avoid duplicates
                    if not any(b['service_category'] == category and b['spd_file'] == filename for b in benefits):
                        benefits.append(benefit)
                break
    
    return benefits

def generate_hrl_syntax(benefits_df: pd.DataFrame) -> str:
    """Generate HRL syntax from extracted benefits"""
    if benefits_df.empty:
        return ""
    
    hrl_rules = []
    hrl_rules.append("// Generated HRL Rules from SPD Documents")
    hrl_rules.append("// " + "="*50)
    hrl_rules.append("")
    
    for _, benefit in benefits_df.iterrows():
        service_category = benefit['service_category']
        in_network = benefit['in_network_coverage']
        out_network = benefit['out_of_network_coverage']
        
        hrl_rules.append(f"// {service_category} Benefits")
        hrl_rules.append(f'IF (ServiceCategory = "{service_category}") THEN')
        
        # Parse in-network coverage
        if in_network and in_network != 'unknown':
            hrl_rules.append('    IF (NetworkStatus = "In-Network") THEN')
            
            if '$' in in_network and 'copay' in in_network.lower():
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', in_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
            elif '%' in in_network:
                percent = re.search(r'(\d+)%', in_network)
                if percent:
                    if 'after deductible' in in_network.lower():
                        hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                        hrl_rules.append(f'            Benefit = {percent.group(1)}% of ServiceCost')
                        hrl_rules.append('        ELSE')
                        hrl_rules.append('            MemberResponsibility = ServiceCost')
                        hrl_rules.append('            ApplyToDeductible = ServiceCost')
                    else:
                        hrl_rules.append(f'        Benefit = {percent.group(1)}% of ServiceCost')
            elif 'not covered' in in_network.lower():
                hrl_rules.append('        Benefit = $0.00')
                hrl_rules.append('        MemberResponsibility = ServiceCost')
        
        # Parse out-of-network coverage
        if out_network and out_network != 'unknown' and out_network != in_network:
            hrl_rules.append('    ELSE IF (NetworkStatus = "Out-of-Network") THEN')
            
            if '$' in out_network and 'copay' in out_network.lower():
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', out_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
            elif '%' in out_network:
                percent = re.search(r'(\d+)%', out_network)
                if percent:
                    if 'after deductible' in out_network.lower():
                        hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                        hrl_rules.append(f'            Benefit = {percent.group(1)}% of AllowedAmount')
                        hrl_rules.append('        ELSE')
                        hrl_rules.append('            MemberResponsibility = ServiceCost')
                        hrl_rules.append('            ApplyToDeductible = ServiceCost')
                    else:
                        hrl_rules.append(f'        Benefit = {percent.group(1)}% of AllowedAmount')
            elif 'not covered' in out_network.lower():
                hrl_rules.append('        Benefit = $0.00')
                hrl_rules.append('        MemberResponsibility = ServiceCost')
        
        hrl_rules.append("")
    
    return '\n'.join(hrl_rules)

def main():
    # Initialize session state
    if 'uploaded_files' not in st.session_state:
        st.session_state.uploaded_files = []
    if 'extracted_data' not in st.session_state:
        st.session_state.extracted_data = pd.DataFrame()
    if 'hrl_syntax' not in st.session_state:
        st.session_state.hrl_syntax = ""
    
    # Header with stats in top right
    st.markdown(f"""
    <div class="top-header">
        <div class="header-left">
            <h1 class="header-title">SPD to HRL Converter</h1>
            <p class="header-subtitle">Transform Summary Plan Documents into HealthRules Language</p>
        </div>
        <div class="stats-horizontal">
            <div class="stat-item">
                <div class="stat-value">40+</div>
                <div class="stat-label">Benefit Categories</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{len(st.session_state.uploaded_files)}</div>
                <div class="stat-label">Files Uploaded</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{len(st.session_state.extracted_data) if not st.session_state.extracted_data.empty else 0}</div>
                <div class="stat-label">Benefits Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">✓</div>
                <div class="stat-label">No AI Required</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # How it works section
    with st.expander("ℹ️ How This Works", expanded=False):
        st.markdown("""
        <div style="color: white;">
        This tool uses advanced pattern matching to extract benefit information:
        
        • ✅ **Searches for 40+ benefit categories** (office visits, emergency room, etc.)  
        • ✅ **Identifies coverage patterns** (copays, coinsurance percentages)  
        • ✅ **Distinguishes network types** (in-network vs out-of-network)  
        • ✅ **Generates HRL syntax** automatically based on patterns
        
        *Best results with SPDs using standard terminology.*
        </div>
        """, unsafe_allow_html=True)
    
    # File Upload Section - Using columns for proper alignment
    st.markdown('<div class="upload-section">', unsafe_allow_html=True)
    col1, col2 = st.columns(2, gap="medium")
    
    with col1:
        st.markdown("""
        <div class="custom-card">
            <h3 class="card-header">📤 Upload SPD Files</h3>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_files = st.file_uploader(
            "Select PDF files",
            type=['pdf'],
            accept_multiple_files=True,
            key="pdf_uploader",
            help="Upload one or more SPD documents in PDF format",
            label_visibility="collapsed"
        )
        
        if uploaded_files:
            st.session_state.uploaded_files = uploaded_files
            st.success(f"✅ {len(uploaded_files)} file(s) uploaded successfully")
    
    with col2:
        st.markdown("""
        <div class="custom-card">
            <h3 class="card-header">📋 Uploaded Files</h3>
        </div>
        """, unsafe_allow_html=True)
        
        if st.session_state.uploaded_files:
            files_html = ""
            for file in st.session_state.uploaded_files:
                file_size_kb = file.size / 1024
                files_html += f"""
                <div class="uploaded-file-item">
                    <span class="file-name">✓ {file.name}</span>
                    <span class="file-size">{file_size_kb:.1f} KB</span>
                </div>
                """
            st.markdown(files_html, unsafe_allow_html=True)
        else:
            st.info("📁 No files uploaded yet")
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Extract Button - Centered
    st.markdown('<div class="extract-button-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        extract_button = st.button(
            "🚀 Start Extraction", 
            disabled=not st.session_state.uploaded_files, 
            use_container_width=True
        )
    st.markdown('</div>', unsafe_allow_html=True)
    
    if extract_button:
        with st.spinner("Analyzing PDFs and extracting benefits..."):
            progress_bar = st.progress(0, text="Starting extraction...")
            all_benefits = []
            
            for idx, file in enumerate(st.session_state.uploaded_files):
                progress = (idx + 1) / len(st.session_state.uploaded_files)
                progress_bar.progress(progress, text=f"Processing: {file.name}")
                
                text = extract_text_from_pdf(file)
                if text:
                    benefits = extract_benefits_from_text(text, file.name)
                    all_benefits.extend(benefits)
            
            progress_bar.empty()
            
            if all_benefits:
                st.session_state.extracted_data = pd.DataFrame(all_benefits)
                st.balloons()
                st.success(f"✅ Extracted {len(all_benefits)} benefit categories successfully!")
            else:
                st.error("❌ No benefits found. Please check if the PDFs contain standard benefit terminology.")
    
    # Display extracted data
    if not st.session_state.extracted_data.empty:
        # Single card container for the entire section
        st.markdown('<div class="custom-card" style="margin-top: 2rem;">', unsafe_allow_html=True)
        st.markdown('<h3 class="card-header">📊 Extracted Benefits</h3>', unsafe_allow_html=True)
        
        # Tabs for better organization
        tab1, tab2 = st.tabs(["📝 Review & Edit", "➕ Add Manual Entry"])
        
        with tab1:
            # Create a copy for editing to avoid modifying the original
            edited_df = st.data_editor(
                st.session_state.extracted_data.copy(),
                column_config={
                    "service_category": st.column_config.TextColumn(
                        "Service Category",
                        width="medium",
                        help="Type of medical service"
                    ),
                    "in_network_coverage": st.column_config.TextColumn(
                        "In-Network Coverage",
                        width="large",
                        help="Coverage details for in-network providers"
                    ),
                    "out_of_network_coverage": st.column_config.TextColumn(
                        "Out-of-Network Coverage",
                        width="large",
                        help="Coverage details for out-of-network providers"
                    ),
                    "spd_file": st.column_config.TextColumn(
                        "Source File",
                        width="medium",
                        disabled=True
                    ),
                },
                hide_index=True,
                use_container_width=True,
                num_rows="dynamic",
                key="benefits_editor"
            )
            # Update session state with edited data
            st.session_state.extracted_data = edited_df
        
        with tab2:
            col1, col2 = st.columns(2)
            with col1:
                new_category = st.text_input("Service Category", placeholder="e.g., Specialist Visit", key="new_category_input")
                new_in_network = st.text_input("In-Network Coverage", placeholder="e.g., $40 copay", key="new_in_network_input")
            with col2:
                new_out_network = st.text_input("Out-of-Network Coverage", placeholder="e.g., 70% after deductible", key="new_out_network_input")
                new_file = st.text_input("Source File", value="Manual Entry", key="new_file_input")
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                if st.button("➕ Add Entry", use_container_width=True, key="add_manual_entry_btn"):
                    if new_category:
                        new_entry = pd.DataFrame([{
                            'service_category': new_category,
                            'in_network_coverage': new_in_network,
                            'out_of_network_coverage': new_out_network,
                            'spd_file': new_file
                        }])
                        st.session_state.extracted_data = pd.concat(
                            [st.session_state.extracted_data, new_entry], 
                            ignore_index=True
                        )
                        st.success("✅ Entry added successfully!")
                    else:
                        st.error("Please enter a service category")
        
        # Close the card div after all content
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Action buttons outside the card
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📥 Export to Excel", use_container_width=True, key="export_excel_btn"):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    edited_df.to_excel(writer, index=False, sheet_name='Benefits')
                output.seek(0)
                
                st.download_button(
                    label="💾 Download",
                    data=output,
                    file_name=f"benefits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    key="download_excel_btn"
                )
        
        with col4:
            if st.button("🔄 Generate HRL", type="primary", use_container_width=True, key="generate_hrl_btn"):
                with st.spinner("Generating HRL syntax..."):
                    hrl_syntax = generate_hrl_syntax(edited_df)
                    st.session_state.hrl_syntax = hrl_syntax
    
    # Display extracted data
    if not st.session_state.extracted_data.empty:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<h3 class="card-header">📊 Extracted Benefits</h3>', unsafe_allow_html=True)
        st.markdown('<p style="color: #6b7280; margin-bottom: 1rem;">You can edit the coverage details below before generating HRL</p>', unsafe_allow_html=True)
        
        # Create tabs for better organization
        tab1, tab2 = st.tabs(["📝 Edit Benefits", "➕ Add Manual Entry"])
        
        with tab1:
            # Create an editable dataframe
            edited_df = st.data_editor(
                st.session_state.extracted_data,
                column_config={
                    "service_category": st.column_config.TextColumn(
                        "Service Category",
                        width="medium",
                        help="The type of medical service"
                    ),
                    "in_network_coverage": st.column_config.TextColumn(
                        "In-Network Coverage",
                        width="large",
                        help="Coverage when using in-network providers"
                    ),
                    "out_of_network_coverage": st.column_config.TextColumn(
                        "Out-of-Network Coverage",
                        width="large",
                        help="Coverage when using out-of-network providers"
                    ),
                    "spd_file": st.column_config.TextColumn(
                        "SPD File Name",
                        width="medium",
                        help="Source document"
                    ),
                },
                hide_index=True,
                use_container_width=True,
                num_rows="dynamic"
            )
            
            # Update session state with edited data
            st.session_state.extracted_data = edited_df
        
        with tab2:
            # Add manual entry section with better layout
            st.markdown('<div style="padding: 1rem;">', unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                new_category = st.text_input("Service Category", placeholder="e.g., Specialist Visit")
                new_in_network = st.text_input("In-Network Coverage", placeholder="e.g., $40 copay")
            with col2:
                new_out_network = st.text_input("Out-of-Network Coverage", placeholder="e.g., 70% after deductible")
                new_file = st.text_input("SPD File Name", value="Manual Entry")
            
            if st.button("➕ Add Entry", use_container_width=True):
                if new_category:
                    new_entry = pd.DataFrame([{
                        'service_category': new_category,
                        'in_network_coverage': new_in_network,
                        'out_of_network_coverage': new_out_network,
                        'spd_file': new_file
                    }])
                    st.session_state.extracted_data = pd.concat([st.session_state.extracted_data, new_entry], ignore_index=True)
                    st.experimental_rerun()
                else:
                    st.error("Please enter a service category")
            st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Action buttons with better styling
        st.markdown("<br>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
        with col1:
            if st.button("📥 Download Excel", use_container_width=True):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    edited_df.to_excel(writer, index=False, sheet_name='Benefits')
                output.seek(0)
                st.download_button(
                    label="💾 Save Excel",
                    data=output,
                    file_name=f"extracted_benefits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
        
        with col4:
            if st.button("🔄 Convert to HRL", type="primary", use_container_width=True):
                with st.spinner("🔨 Generating HRL syntax..."):
                    hrl_syntax = generate_hrl_syntax(edited_df)
                    st.session_state.hrl_syntax = hrl_syntax
    
    # Display HRL syntax
    if st.session_state.hrl_syntax:
        # HRL Output Section
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown("""
            <div class="custom-card" style="margin-top: 2rem;">
                <h3 class="card-header">📝 Generated HRL Syntax</h3>
            </div>
            """, unsafe_allow_html=True)
            
            st.code(st.session_state.hrl_syntax, language="sql")
            
            st.download_button(
                label="📥 Download HRL File",
                data=st.session_state.hrl_syntax,
                file_name=f"hrl_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hrl",
                mime="text/plain",
                use_container_width=True
            )
        
        with col2:
            # Quick Reference
            st.markdown("""
            <div class="custom-card" style="margin-top: 2rem;">
                <h3 class="card-header">📚 Quick Reference</h3>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander("Copay Pattern", expanded=False):
                st.code("""IF (ServiceCategory = "Office Visit") THEN
    IF (NetworkStatus = "In-Network") THEN
        MemberResponsibility = $25.00
    ELSE
        MemberResponsibility = $50.00""", language="sql")
            
            with st.expander("Coinsurance Pattern", expanded=False):
                st.code("""IF (ServiceCategory = "Specialist") THEN
    IF (NetworkStatus = "In-Network") THEN
        Benefit = 80% of ServiceCost
    ELSE
        Benefit = 70% of AllowedAmount""", language="sql")
            
            with st.expander("Deductible Pattern", expanded=False):
                st.code("""IF (DeductibleMet = FALSE) THEN
    MemberResponsibility = ServiceCost
    ApplyToDeductible = ServiceCost
ELSE
    Benefit = 80% of ServiceCost""", language="sql")
    
    # Footer
    st.markdown("""
    <div class="custom-footer">
        SPD to HRL Converter • Rule-Based Processing • No AI Required
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
