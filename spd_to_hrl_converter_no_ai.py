import streamlit as st
import pandas as pd
import PyPDF2
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

# Common coverage patterns - Enhanced for better extraction
COVERAGE_PATTERNS = {
    'copay': r'\$\s*(\d+(?:\.\d{2})?)\s*(?:copay|co-pay|per visit)',
    'coinsurance': r'(\d+)\s*%\s*(?:coinsurance|covered|after deductible|of)',
    'percentage': r'(\d+)\s*%',
    'deductible': r'(?:after deductible|deductible applies|subject to deductible)',
    'no_charge': r'(?:no charge|covered in full|100%|0%|waived)',
    'not_covered': r'(?:not covered|0% covered|excluded)',
    'dollar_limit': r'\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(?:maximum|max|limit)',
    'visit_limit': r'(\d+)\s*(?:visits?|days?|treatments?)\s*(?:per year|annually|maximum)'
}

def extract_text_from_pdf(file) -> str:
    """Extract text content from PDF file"""
    try:
        pdf_reader = PyPDF2.PdfReader(file)
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
    
    # First, check for percentage values (most common in SPDs)
    percentage_matches = re.findall(r'(\d+)\s*%', text_segment)
    if percentage_matches:
        # Get the first percentage found
        coverage['type'] = 'coinsurance'
        coverage['value'] = f"{percentage_matches[0]}%"
        
        # Check for additional context
        if 'after deductible' in text_lower:
            coverage['details'] = 'after deductible'
        elif 'of' in text_lower:
            # Look for what it's a percentage of
            of_match = re.search(r'(\d+%)\s+of\s+([^,\.\n]+)', text_segment, re.IGNORECASE)
            if of_match:
                coverage['details'] = f'of {of_match.group(2).strip()}'
        else:
            coverage['details'] = 'coinsurance'
        return coverage
    
    # Check for copay
    copay_match = re.search(r'\$\s*(\d+(?:\.\d{2})?)', text_segment)
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
    
    return coverage

def extract_benefits_from_text(text: str, filename: str) -> List[Dict]:
    """Extract benefit information dynamically from the document"""
    benefits = []
    
    # Split text into lines for better processing
    lines = text.split('\n')
    
    # Clean lines - remove extra spaces and empty lines
    cleaned_lines = [line.strip() for line in lines if line.strip()]
    
    # Method 1: Look for lines containing both In-Network and Out-of-Network percentages
    for i, line in enumerate(cleaned_lines):
        # Skip lines that are likely headers or page numbers
        if any(skip in line.lower() for skip in ['page', 'effective date', 'plan id', 'summary', 'table of contents']):
            continue
            
        # Look for lines with percentage patterns
        if '%' in line:
            # Pattern 1: Service name followed by two percentages
            # Example: "Primary Care Physician Visit 80% 60%"
            pattern1 = re.match(r'^([A-Za-z\s\-/,&\(\)]+?)\s+(\d+%)\s+(\d+%)', line)
            if pattern1:
                service = pattern1.group(1).strip()
                in_network = pattern1.group(2)
                out_network = pattern1.group(3)
                
                if len(service) > 3:  # Valid service name
                    benefits.append({
                        'service_category': service,
                        'in_network_coverage': in_network,
                        'out_of_network_coverage': out_network,
                        'spd_file': filename
                    })
                    continue
            
            # Pattern 2: Service on one line, percentages on next line(s)
            # Check if next line has percentages
            if i + 1 < len(cleaned_lines) and '%' in cleaned_lines[i + 1]:
                next_line = cleaned_lines[i + 1]
                percentages = re.findall(r'(\d+%)', next_line)
                
                if len(percentages) >= 2 and not '%' in line:
                    # Current line might be the service name
                    service = line.strip()
                    if len(service) > 3 and len(service) < 100 and not any(char.isdigit() for char in service[:3]):
                        benefits.append({
                            'service_category': service,
                            'in_network_coverage': percentages[0],
                            'out_of_network_coverage': percentages[1],
                            'spd_file': filename
                        })
                        continue
    
    # Method 2: Look for table-like structures with clear In-Network/Out-of-Network columns
    in_network_indices = []
    out_network_indices = []
    
    # Find header rows
    for i, line in enumerate(cleaned_lines):
        if 'in-network' in line.lower() or 'in network' in line.lower():
            # This might be a header row
            if 'out-of-network' in line.lower() or 'out of network' in line.lower() or 'non-network' in line.lower():
                # Found a header with both network types
                # Try to parse the table below this header
                for j in range(i + 1, min(i + 50, len(cleaned_lines))):  # Look at next 50 lines
                    table_line = cleaned_lines[j]
                    
                    # Extract percentages from this line
                    percentages = re.findall(r'(\d+%)', table_line)
                    
                    if len(percentages) >= 2:
                        # Find the service name - could be at the beginning of this line or on a previous line
                        service_name = ""
                        
                        # Check if service name is at the start of current line
                        service_match = re.match(r'^([A-Za-z\s\-/,&\(\)]+?)(?:\s+\d+%|\s*$)', table_line)
                        if service_match:
                            service_name = service_match.group(1).strip()
                        else:
                            # Look at previous line for service name
                            if j > 0:
                                prev_line = cleaned_lines[j - 1]
                                if not '%' in prev_line and len(prev_line) > 3:
                                    service_name = prev_line.strip()
                        
                        if service_name and len(service_name) > 3:
                            # Remove any trailing colons or dashes
                            service_name = service_name.rstrip(':- ')
                            
                            benefits.append({
                                'service_category': service_name,
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            })
    
    # Method 3: Look for specific patterns like "Service: In-Network: X% Out-of-Network: Y%"
    pattern = re.compile(
        r'([A-Za-z\s\-/,&\(\)]+?)[\s:]+' +
        r'(?:In[\s\-]*Network|Network|Participating)[\s:]+(\d+%)' +
        r'.*?' +
        r'(?:Out[\s\-]*of[\s\-]*Network|Non[\s\-]*Network|Non[\s\-]*Participating)[\s:]+(\d+%)',
        re.IGNORECASE | re.DOTALL
    )
    
    matches = pattern.finditer(text)
    for match in matches:
        service = match.group(1).strip().rstrip(':- ')
        in_network = match.group(2)
        out_network = match.group(3)
        
        if len(service) > 3:
            benefit = {
                'service_category': service,
                'in_network_coverage': in_network,
                'out_of_network_coverage': out_network,
                'spd_file': filename
            }
            # Check for duplicates
            if not any(b['service_category'].lower() == benefit['service_category'].lower() for b in benefits):
                benefits.append(benefit)
    
    # Method 4: Extract from structured benefit listings
    # Look for sections that list benefits with clear percentage values
    benefit_section = False
    current_service = ""
    
    for i, line in enumerate(cleaned_lines):
        # Check if we're in a benefits section
        if any(keyword in line.lower() for keyword in ['covered services', 'benefit summary', 'coverage level', 'member cost share']):
            benefit_section = True
            continue
        
        if benefit_section:
            # Look for service names followed by coverage info
            if line and not '%' in line and not any(char.isdigit() for char in line[:3]):
                # Potential service name
                if len(line) > 3 and len(line) < 100:
                    current_service = line.strip().rstrip(':- ')
            
            elif current_service and '%' in line:
                # Extract percentages
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    benefit = {
                        'service_category': current_service,
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    # Check for duplicates
                    if not any(b['service_category'].lower() == benefit['service_category'].lower() for b in benefits):
                        benefits.append(benefit)
                    current_service = ""  # Reset for next service
    
    # Remove any duplicate entries based on service category
    unique_benefits = []
    seen_services = set()
    
    for benefit in benefits:
        service_lower = benefit['service_category'].lower()
        if service_lower not in seen_services:
            seen_services.add(service_lower)
            unique_benefits.append(benefit)
    
    return unique_benefits

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
        
        hrl_rules.append(f"// {service_category}")
        hrl_rules.append(f'IF (ServiceCategory = "{service_category}") THEN')
        
        # Parse in-network coverage
        if in_network and in_network != 'unknown':
            hrl_rules.append('    IF (NetworkStatus = "In-Network") THEN')
            
            # Check if it's a percentage
            percent_match = re.search(r'(\d+)%', in_network)
            if percent_match:
                percentage = percent_match.group(1)
                # Check for deductible context
                if 'after deductible' in in_network.lower() or 'deductible' in in_network.lower():
                    hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                    hrl_rules.append(f'            Benefit = {percentage}% of ServiceCost')
                    hrl_rules.append('        ELSE')
                    hrl_rules.append('            MemberResponsibility = ServiceCost')
                    hrl_rules.append('            ApplyToDeductible = ServiceCost')
                else:
                    hrl_rules.append(f'        Benefit = {percentage}% of ServiceCost')
            # Check if it's a copay
            elif '

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
        <div style="color: Black;">
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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
    main() in in_network:
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', in_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
            elif 'not covered' in in_network.lower():
                hrl_rules.append('        Benefit = $0.00')
                hrl_rules.append('        MemberResponsibility = ServiceCost')
        
        # Parse out-of-network coverage
        if out_network and out_network != 'unknown' and out_network != in_network:
            hrl_rules.append('    ELSE IF (NetworkStatus = "Out-of-Network") THEN')
            
            # Check if it's a percentage
            percent_match = re.search(r'(\d+)%', out_network)
            if percent_match:
                percentage = percent_match.group(1)
                # Check for deductible context
                if 'after deductible' in out_network.lower() or 'deductible' in out_network.lower():
                    hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                    hrl_rules.append(f'            Benefit = {percentage}% of AllowedAmount')
                    hrl_rules.append('        ELSE')
                    hrl_rules.append('            MemberResponsibility = ServiceCost')
                    hrl_rules.append('            ApplyToDeductible = ServiceCost')
                else:
                    hrl_rules.append(f'        Benefit = {percentage}% of AllowedAmount')
            # Check if it's a copay
            elif '

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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
    main() in out_network:
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', out_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
    main() in full_match:

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
        
        hrl_rules.append(f"// {service_category}")
        hrl_rules.append(f'IF (ServiceCategory = "{service_category}") THEN')
        
        # Parse in-network coverage
        if in_network and in_network != 'unknown':
            hrl_rules.append('    IF (NetworkStatus = "In-Network") THEN')
            
            # Check if it's a percentage
            percent_match = re.search(r'(\d+)%', in_network)
            if percent_match:
                percentage = percent_match.group(1)
                # Check for deductible context
                if 'after deductible' in in_network.lower() or 'deductible' in in_network.lower():
                    hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                    hrl_rules.append(f'            Benefit = {percentage}% of ServiceCost')
                    hrl_rules.append('        ELSE')
                    hrl_rules.append('            MemberResponsibility = ServiceCost')
                    hrl_rules.append('            ApplyToDeductible = ServiceCost')
                else:
                    hrl_rules.append(f'        Benefit = {percentage}% of ServiceCost')
            # Check if it's a copay
            elif '

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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
    main() in in_network:
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', in_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
            elif 'not covered' in in_network.lower():
                hrl_rules.append('        Benefit = $0.00')
                hrl_rules.append('        MemberResponsibility = ServiceCost')
        
        # Parse out-of-network coverage
        if out_network and out_network != 'unknown' and out_network != in_network:
            hrl_rules.append('    ELSE IF (NetworkStatus = "Out-of-Network") THEN')
            
            # Check if it's a percentage
            percent_match = re.search(r'(\d+)%', out_network)
            if percent_match:
                percentage = percent_match.group(1)
                # Check for deductible context
                if 'after deductible' in out_network.lower() or 'deductible' in out_network.lower():
                    hrl_rules.append('        IF (DeductibleMet = TRUE) THEN')
                    hrl_rules.append(f'            Benefit = {percentage}% of AllowedAmount')
                    hrl_rules.append('        ELSE')
                    hrl_rules.append('            MemberResponsibility = ServiceCost')
                    hrl_rules.append('            ApplyToDeductible = ServiceCost')
                else:
                    hrl_rules.append(f'        Benefit = {percentage}% of AllowedAmount')
            # Check if it's a copay
            elif '

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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
    main() in out_network:
                amount = re.search(r'\$(\d+(?:\.\d{2})?)', out_network)
                if amount:
                    hrl_rules.append(f'        MemberResponsibility = ${amount.group(1)}')
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
    main() in full_match:
                        # Extract copay amounts if present
                        copays = re.findall(r'\$(\d+)', full_match)
                        if len(copays) >= 2:
                            in_network_cov = f'${copays[0]} copay'
                            out_network_cov = f'${copays[1]} copay'
                    
                    benefit = {
                        'service_category': service.title().replace('Pcp', 'PCP'),
                        'in_network_coverage': in_network_cov,
                        'out_of_network_coverage': out_network_cov,
                        'spd_file': filename
                    }
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
            except:
                continue
    
    # Method 3: Extract from table-like structures
    # Look for lines that have multiple percentage values
    for i, line in enumerate(lines):
        percentages = re.findall(r'(\d+%)', line)
        if len(percentages) >= 2:
            # Look at previous lines for the service name
            for j in range(max(0, i-3), i):
                potential_service = lines[j].strip()
                # Check if it's a valid service name
                if (len(potential_service) > 3 and 
                    len(potential_service) < 50 and 
                    not any(char.isdigit() for char in potential_service[:3]) and
                    not any(skip in potential_service.lower() for skip in ['page', 'date', 'effective', 'plan id'])):
                    
                    benefit = {
                        'service_category': potential_service.title(),
                        'in_network_coverage': percentages[0],
                        'out_of_network_coverage': percentages[1],
                        'spd_file': filename
                    }
                    
                    # Add deductible context if present
                    context_text = ' '.join(lines[max(0, i-2):min(len(lines), i+2)]).lower()
                    if 'after deductible' in context_text:
                        benefit['in_network_coverage'] += ' after deductible'
                        benefit['out_of_network_coverage'] += ' after deductible'
                    
                    # Check for duplicates
                    if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                        benefits.append(benefit)
                    break
    
    # If no benefits found with the above methods, try a more general approach
    if not benefits:
        # Look for any line with two percentages
        for line in lines:
            if line.strip() and '%' in line:
                # Extract all percentages from the line
                percentages = re.findall(r'(\d+%)', line)
                if len(percentages) >= 2:
                    # Try to extract a service name from the beginning of the line
                    service_match = re.match(r'^([A-Za-z\s\-/,&]+?)[\s:]+', line)
                    if service_match:
                        service = service_match.group(1).strip()
                        if len(service) > 3:
                            benefit = {
                                'service_category': service.title(),
                                'in_network_coverage': percentages[0],
                                'out_of_network_coverage': percentages[1],
                                'spd_file': filename
                            }
                            if not any(b['service_category'] == benefit['service_category'] for b in benefits):
                                benefits.append(benefit)
    
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
