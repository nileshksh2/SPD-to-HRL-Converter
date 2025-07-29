import streamlit as st
import pandas as pd
import pypdf
import io
import re
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import json

# Page configuration
st.set_page_config(
    page_title="SPD to HRL Converter (Enhanced)",
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

# Enhanced benefit categories with variations
BENEFIT_CATEGORIES = {
    # Primary Care
    'Primary Care': ['primary care', 'pcp', 'family practice', 'general practice', 'family doctor'],
    'Office Visit': ['office visit', 'physician visit', 'doctor visit', 'clinic visit'],
    'Specialist Visit': ['specialist', 'specialty care', 'specialist visit', 'referral'],
    
    # Emergency Services
    'Emergency Room': ['emergency room', 'emergency department', 'er visit', 'emergency services'],
    'Urgent Care': ['urgent care', 'urgent care center', 'walk-in clinic'],
    'Ambulance': ['ambulance', 'emergency transport', 'air ambulance', 'ground ambulance'],
    
    # Hospital Services
    'Inpatient Hospital': ['inpatient', 'hospital admission', 'hospital stay', 'room and board'],
    'Outpatient Hospital': ['outpatient hospital', 'outpatient facility', 'hospital outpatient'],
    'Surgery': ['surgery', 'surgical', 'outpatient surgery', 'inpatient surgery', 'ambulatory surgery'],
    
    # Preventive Care
    'Preventive Care': ['preventive', 'preventative', 'wellness', 'routine care', 'annual physical'],
    'Routine Wellness': ['routine wellness', 'wellness visit', 'annual exam', 'physical exam'],
    'Immunizations': ['immunizations', 'vaccines', 'vaccination', 'flu shot'],
    'Screenings': ['screening', 'mammogram', 'colonoscopy', 'cancer screening'],
    
    # Mental Health
    'Mental Health': ['mental health', 'behavioral health', 'psychiatric', 'psychologist'],
    'Substance Abuse': ['substance abuse', 'drug treatment', 'alcohol treatment', 'addiction'],
    
    # Therapy Services
    'Physical Therapy': ['physical therapy', 'pt', 'physiotherapy', 'rehabilitation'],
    'Occupational Therapy': ['occupational therapy', 'ot', 'occupational'],
    'Speech Therapy': ['speech therapy', 'speech pathology', 'speech language'],
    'Chiropractic': ['chiropractic', 'chiropractor', 'chiropractic care'],
    
    # Diagnostic Services
    'Laboratory': ['laboratory', 'lab services', 'lab work', 'blood work', 'lab tests'],
    'X-ray': ['x-ray', 'xray', 'radiography', 'imaging'],
    'Advanced Imaging': ['mri', 'ct scan', 'pet scan', 'advanced imaging', 'diagnostic imaging'],
    
    # Prescription Drugs
    'Generic Drugs': ['generic', 'generic drugs', 'generic medication'],
    'Brand Drugs': ['brand', 'brand name', 'preferred brand', 'non-preferred brand'],
    'Specialty Drugs': ['specialty', 'specialty pharmacy', 'specialty medication'],
    
    # Other Services
    'Maternity': ['maternity', 'pregnancy', 'prenatal', 'childbirth', 'delivery'],
    'Dental': ['dental', 'dentist', 'oral health'],
    'Vision': ['vision', 'eye care', 'optometry', 'glasses', 'contacts'],
    'Hearing': ['hearing', 'hearing aids', 'audiology'],
    'Durable Medical Equipment': ['dme', 'durable medical equipment', 'medical equipment'],
    'Home Health': ['home health', 'home care', 'home nursing'],
    'Skilled Nursing': ['skilled nursing', 'nursing home', 'snf'],
    'Hospice': ['hospice', 'hospice care', 'end of life care']
}

# Enhanced coverage patterns with more variations
COVERAGE_PATTERNS = {
    'copay': [
        r'\$\s*(\d+(?:\.\d{2})?)\s*(?:copay|co-pay|per visit|copayment)',
        r'(\d+)\s*dollar(?:s)?\s*(?:copay|co-pay)',
        r'copay.*?\$\s*(\d+(?:\.\d{2})?)',
        r'pay.*?\$\s*(\d+(?:\.\d{2})?)'
    ],
    'coinsurance': [
        r'(\d+)\s*%\s*(?:coinsurance|covered|after deductible|of|coverage)',
        r'(\d+)\s*percent\s*(?:coinsurance|covered)',
        r'plan pays\s*(\d+)\s*%',
        r'(\d+)%\s*after\s*deductible'
    ],
    'deductible': [
        r'after deductible',
        r'deductible applies',
        r'subject to deductible',
        r'deductible then',
        r'once deductible is met'
    ],
    'no_charge': [
        r'no charge',
        r'covered in full',
        r'100%\s*covered',
        r'0%\s*coinsurance',
        r'waived',
        r'free',
        r'no cost'
    ],
    'not_covered': [
        r'not covered',
        r'0%\s*covered',
        r'excluded',
        r'no benefits',
        r'no coverage'
    ],
    'dollar_amount': [
        r'\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)',
        r'(\d+(?:,\d{3})*)\s*dollars?'
    ]
}

def extract_text_from_pdf(file) -> str:
    """Extract text content from PDF file with better error handling"""
    try:
        pdf_reader = pypdf.PdfReader(file)
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        return text
    except Exception as e:
        st.error(f"Error reading PDF {file.name}: {str(e)}")
        return ""

def clean_and_normalize_text(text: str) -> str:
    """Clean and normalize text for better processing"""
    # Remove excessive whitespace but preserve line breaks
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n\s*\n', '\n\n', text)
    
    # Normalize currency symbols and percentages
    text = re.sub(r'[$]\s+', '$', text)
    text = re.sub(r'(\d)\s+%', r'\1%', text)
    
    # Fix common OCR issues
    text = text.replace('O%', '0%')
    text = text.replace('l00%', '100%')
    text = text.replace('$O', '$0')
    
    return text.strip()

def find_benefit_sections(text: str) -> List[Dict]:
    """Find potential benefit sections using multiple strategies"""
    sections = []
    lines = text.split('\n')
    
    # Strategy 1: Look for table-like structures
    for i, line in enumerate(lines):
        line_clean = line.strip()
        if not line_clean:
            continue
            
        # Check if line contains benefit keywords
        for category, keywords in BENEFIT_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in line_clean.lower():
                    # Get extended context (up to 10 lines after)
                    context_lines = []
                    for j in range(i, min(len(lines), i + 10)):
                        context_lines.append(lines[j])
                        # Stop if we hit another major section
                        if j > i and any(cat.lower() in lines[j].lower() 
                                       for cat in BENEFIT_CATEGORIES.keys() 
                                       if cat != category):
                            break
                    
                    sections.append({
                        'category': category,
                        'text': '\n'.join(context_lines),
                        'start_line': i,
                        'keyword_matched': keyword
                    })
                    break
    
    # Strategy 2: Look for schedule of benefits sections
    schedule_pattern = r'(?i)schedule\s+of\s+benefits.*?(?=\n\n|\Z)'
    schedule_matches = re.finditer(schedule_pattern, text, re.DOTALL)
    
    for match in schedule_matches:
        schedule_text = match.group()
        # Parse this section more carefully
        schedule_sections = parse_schedule_section(schedule_text)
        sections.extend(schedule_sections)
    
    return sections

def parse_schedule_section(text: str) -> List[Dict]:
    """Parse a schedule of benefits section"""
    sections = []
    lines = text.split('\n')
    
    current_category = None
    current_text = []
    
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        
        # Check if this line starts a new benefit category
        found_category = None
        for category, keywords in BENEFIT_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in line_clean.lower() and len(line_clean) < 100:
                    found_category = category
                    break
            if found_category:
                break
        
        if found_category:
            # Save previous category if exists
            if current_category and current_text:
                sections.append({
                    'category': current_category,
                    'text': '\n'.join(current_text),
                    'start_line': 0,
                    'keyword_matched': current_category.lower()
                })
            
            # Start new category
            current_category = found_category
            current_text = [line]
        else:
            # Add to current category
            if current_category:
                current_text.append(line)
    
    # Don't forget the last category
    if current_category and current_text:
        sections.append({
            'category': current_category,
            'text': '\n'.join(current_text),
            'start_line': 0,
            'keyword_matched': current_category.lower()
        })
    
    return sections

def extract_coverage_details(text: str) -> Dict[str, str]:
    """Extract coverage details with improved pattern matching"""
    text_lower = text.lower()
    
    # Initialize result
    result = {
        'in_network': '',
        'out_of_network': '',
        'type': 'unknown',
        'details': []
    }
    
    # Split text into network sections if possible
    network_split = re.split(r'(?i)(?:out.of.network|non.network|out.network)', text)
    in_network_text = network_split[0] if network_split else text
    out_network_text = network_split[1] if len(network_split) > 1 else ""
    
    # Extract in-network coverage
    in_coverage = extract_single_coverage(in_network_text)
    if in_coverage:
        result['in_network'] = in_coverage
    
    # Extract out-of-network coverage
    if out_network_text:
        out_coverage = extract_single_coverage(out_network_text)
        if out_coverage:
            result['out_of_network'] = out_coverage
    
    # If no network split found, try to find both in the same text
    if not result['out_of_network']:
        # Look for common patterns like "In-Network: X, Out-of-Network: Y"
        network_pattern = r'(?i)in.network[:\s]*([^,\n]+)(?:.*?)out.of.network[:\s]*([^\n]+)'
        match = re.search(network_pattern, text)
        if match:
            result['in_network'] = match.group(1).strip()
            result['out_of_network'] = match.group(2).strip()
    
    # Determine coverage type
    if '$' in result['in_network'] and any(word in result['in_network'].lower() 
                                         for word in ['copay', 'co-pay']):
        result['type'] = 'copay'
    elif '%' in result['in_network']:
        result['type'] = 'coinsurance'
    elif any(phrase in text_lower for phrase in ['no charge', '100%', 'covered in full']):
        result['type'] = 'covered_100'
    elif any(phrase in text_lower for phrase in ['not covered', 'excluded']):
        result['type'] = 'not_covered'
    
    return result

def extract_single_coverage(text: str) -> str:
    """Extract coverage from a single text segment"""
    text = text.strip()
    if not text:
        return ""
    
    # Try copay patterns first
    for pattern in COVERAGE_PATTERNS['copay']:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            amount = match.group(1)
            return f"${amount} copay"
    
    # Try coinsurance patterns
    for pattern in COVERAGE_PATTERNS['coinsurance']:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            percent = match.group(1)
            # Check if after deductible
            if any(re.search(ded_pattern, text, re.IGNORECASE) 
                   for ded_pattern in COVERAGE_PATTERNS['deductible']):
                return f"{percent}% after deductible"
            else:
                return f"{percent}% coinsurance"
    
    # Check for no charge patterns
    for pattern in COVERAGE_PATTERNS['no_charge']:
        if re.search(pattern, text, re.IGNORECASE):
            return "100% covered"
    
    # Check for not covered patterns
    for pattern in COVERAGE_PATTERNS['not_covered']:
        if re.search(pattern, text, re.IGNORECASE):
            return "Not covered"
    
    # Try to extract any dollar amount or percentage as fallback
    dollar_match = re.search(r'\$\s*(\d+(?:\.\d{2})?)', text)
    if dollar_match:
        return f"${dollar_match.group(1)}"
    
    percent_match = re.search(r'(\d+)\s*%', text)
    if percent_match:
        return f"{percent_match.group(1)}%"
    
    # Return first meaningful phrase if nothing else found
    sentences = text.split('.')
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) > 10 and len(sentence) < 100:
            return sentence
    
    return text[:100] + "..." if len(text) > 100 else text

def extract_benefits_from_text(text: str, filename: str) -> List[Dict]:
    """Enhanced benefit extraction with multiple strategies"""
    text = clean_and_normalize_text(text)
    benefits = []
    
    # Find all potential benefit sections
    sections = find_benefit_sections(text)
    
    # Remove duplicates and merge similar sections
    unique_sections = {}
    for section in sections:
        category = section['category']
        if category not in unique_sections:
            unique_sections[category] = section
        else:
            # Merge text if we found multiple sections for same category
            existing_text = unique_sections[category]['text']
            new_text = section['text']
            if len(new_text) > len(existing_text):
                unique_sections[category] = section
    
    # Extract coverage details for each unique section
    for category, section in unique_sections.items():
        coverage = extract_coverage_details(section['text'])
        
        # Only add if we found meaningful coverage information
        if coverage['in_network'] or coverage['out_of_network']:
            benefit = {
                'service_category': category,
                'in_network_coverage': coverage['in_network'] or 'Not specified',
                'out_of_network_coverage': coverage['out_of_network'] or 'Not specified',
                'coverage_type': coverage['type'],
                'spd_file': filename,
                'raw_text': section['text'][:200] + "..." if len(section['text']) > 200 else section['text']
            }
            benefits.append(benefit)
    
    return benefits

def generate_hrl_syntax(benefits_df: pd.DataFrame) -> str:
    """Generate enhanced HRL syntax with better logic"""
    if benefits_df.empty:
        return ""
    
    hrl_rules = []
    hrl_rules.append("// Generated HRL Rules from SPD Documents")
    hrl_rules.append("// " + "="*60)
    hrl_rules.append(f"// Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    hrl_rules.append(f"// Total Benefits: {len(benefits_df)}")
    hrl_rules.append("// " + "="*60)
    hrl_rules.append("")
    
    for idx, benefit in benefits_df.iterrows():
        service_category = benefit['service_category']
        in_network = benefit['in_network_coverage']
        out_network = benefit['out_of_network_coverage']
        
        hrl_rules.append(f"// Rule {idx + 1}: {service_category}")
        hrl_rules.append("-" * 40)
        hrl_rules.append(f'IF (ServiceCategory = "{service_category}") THEN {{')
        
        # Generate in-network rules
        if in_network and in_network != 'Not specified':
            hrl_rules.append('    IF (NetworkStatus = "In-Network") THEN {')
            in_network_rules = generate_coverage_rules(in_network, "In-Network")
            for rule in in_network_rules:
                hrl_rules.append(f'        {rule}')
            hrl_rules.append('    }')
        
        # Generate out-of-network rules
        if out_network and out_network != 'Not specified' and out_network != in_network:
            hrl_rules.append('    ELSE IF (NetworkStatus = "Out-of-Network") THEN {')
            out_network_rules = generate_coverage_rules(out_network, "Out-of-Network")
            for rule in out_network_rules:
                hrl_rules.append(f'        {rule}')
            hrl_rules.append('    }')
        
        # Default case
        hrl_rules.append('    ELSE {')
        hrl_rules.append('        // Default case - review manually')
        hrl_rules.append('        Benefit = $0.00;')
        hrl_rules.append('        MemberResponsibility = ServiceCost;')
        hrl_rules.append('    }')
        
        hrl_rules.append('}')
        hrl_rules.append("")
    
    return '\n'.join(hrl_rules)

def generate_coverage_rules(coverage_text: str, network_type: str) -> List[str]:
    """Generate specific HRL rules based on coverage text"""
    rules = []
    coverage_lower = coverage_text.lower()
    
    # Copay logic
    copay_match = re.search(r'\$(\d+(?:\.\d{2})?)', coverage_text)
    if copay_match and 'copay' in coverage_lower:
        amount = copay_match.group(1)
        rules.append(f'MemberResponsibility = ${amount};')
        rules.append('ApplyToDeductible = FALSE;')
        return rules
    
    # Percentage coverage
    percent_match = re.search(r'(\d+)%', coverage_text)
    if percent_match:
        percent = int(percent_match.group(1))
        
        if 'after deductible' in coverage_lower:
            rules.append('IF (DeductibleMet = TRUE) THEN {')
            if network_type == "In-Network":
                rules.append(f'    Benefit = {percent}% of ServiceCost;')
            else:
                rules.append(f'    Benefit = {percent}% of AllowedAmount;')
            rules.append('} ELSE {')
            rules.append('    MemberResponsibility = ServiceCost;')
            rules.append('    ApplyToDeductible = ServiceCost;')
            rules.append('}')
        else:
            if network_type == "In-Network":
                rules.append(f'Benefit = {percent}% of ServiceCost;')
            else:
                rules.append(f'Benefit = {percent}% of AllowedAmount;')
            
            if percent == 100:
                rules.append('MemberResponsibility = $0.00;')
            else:
                rules.append(f'MemberResponsibility = {100-percent}% of ServiceCost;')
        
        return rules
    
    # Not covered
    if 'not covered' in coverage_lower or 'excluded' in coverage_lower:
        rules.append('Benefit = $0.00;')
        rules.append('MemberResponsibility = ServiceCost;')
        rules.append('ApplyToDeductible = FALSE;')
        return rules
    
    # Covered in full
    if any(phrase in coverage_lower for phrase in ['100%', 'covered in full', 'no charge']):
        rules.append('Benefit = ServiceCost;')
        rules.append('MemberResponsibility = $0.00;')
        rules.append('ApplyToDeductible = FALSE;')
        return rules
    
    # Default fallback
    rules.append('// Manual review required for: ' + coverage_text[:50])
    rules.append('Benefit = $0.00;')
    rules.append('MemberResponsibility = ServiceCost;')
    
    return rules

# Add custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
    .upload-section {
        border: 2px dashed #667eea;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        margin: 1rem 0;
    }
    .extraction-stats {
        display: flex;
        justify-content: space-around;
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .stat-item {
        text-align: center;
    }
    .stat-number {
        font-size: 2rem;
        font-weight: bold;
        color: #667eea;
    }
    .stat-label {
        font-size: 0.9rem;
        color: #666;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>📄 Enhanced SPD to HRL Converter</h1>
        <p>Advanced pattern matching for accurate benefit extraction</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show stats
    if st.session_state.extracted_data is not None and not st.session_state.extracted_data.empty:
        total_benefits = len(st.session_state.extracted_data)
        categories = st.session_state.extracted_data['service_category'].nunique()
        files_processed = st.session_state.extracted_data['spd_file'].nunique()
        
        st.markdown(f"""
        <div class="extraction-stats">
            <div class="stat-item">
                <div class="stat-number">{total_benefits}</div>
                <div class="stat-label">Benefits Extracted</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{categories}</div>
                <div class="stat-label">Categories Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{files_processed}</div>
                <div class="stat-label">Files Processed</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{len(BENEFIT_CATEGORIES)}</div>
                <div class="stat-label">Categories Searched</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # File upload
    st.markdown('<div class="upload-section">', unsafe_allow_html=True)
    uploaded_files = st.file_uploader(
        "Upload SPD Documents (PDF format)",
        type=['pdf'],
        accept_multiple_files=True,
        help="Select one or more SPD documents in PDF format"
    )
    st.markdown('</div>', unsafe_allow_html=True)
    
    if uploaded_files:
        st.session_state.uploaded_files = uploaded_files
        st.success(f"✅ {len(uploaded_files)} file(s) uploaded successfully")
        
        # Show file details
        with st.expander("📁 Uploaded Files", expanded=True):
            for file in uploaded_files:
                file_size_mb = file.size / (1024 * 1024)
                st.write(f"• **{file.name}** ({file_size_mb:.1f} MB)")
    
    # Extraction button
    if st.button("🚀 Extract Benefits", 
                disabled=not st.session_state.uploaded_files,
                use_container_width=True):
        
        with st.spinner("Processing documents and extracting benefits..."):
            progress_bar = st.progress(0, text="Starting extraction...")
            all_benefits = []
            
            for idx, file in enumerate(st.session_state.uploaded_files):
                progress = (idx + 1) / len(st.session_state.uploaded_files)
                progress_bar.progress(progress, text=f"Processing: {file.name}")
                
                # Extract text
                text = extract_text_from_pdf(file)
                if text:
                    # Extract benefits
                    benefits = extract_benefits_from_text(text, file.name)
                    all_benefits.extend(benefits)
                    
                    st.info(f"Found {len(benefits)} benefits in {file.name}")
            
            progress_bar.empty()
            
            if all_benefits:
                st.session_state.extracted_data = pd.DataFrame(all_benefits)
                st.balloons()
                st.success(f"✅ Successfully extracted {len(all_benefits)} benefits from {len(st.session_state.uploaded_files)} files!")
            else:
                st.error("❌ No benefits found. Please check if the PDFs contain recognizable benefit information.")
    
    # Display extracted data
    if st.session_state.extracted_data is not None and not st.session_state.extracted_data.empty:
        st.markdown("### 📊 Extracted Benefits")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            categories = ['All'] + list(st.session_state.extracted_data['service_category'].unique())
            selected_category = st.selectbox("Filter by Category", categories)
        
        with col2:
            files = ['All'] + list(st.session_state.extracted_data['spd_file'].unique())
            selected_file = st.selectbox("Filter by File", files)
        
        # Apply filters
        filtered_df = st.session_state.extracted_data.copy()
        if selected_category != 'All':
            filtered_df = filtered_df[filtered_df['service_category'] == selected_category]
        if selected_file != 'All':
            filtered_df = filtered_df[filtered_df['spd_file'] == selected_file]
        
        # Display data editor
        edited_df = st.data_editor(
            filtered_df,
            column_config={
                "service_category": st.column_config.SelectboxColumn(
                    "Service Category",
                    options=list(BENEFIT_CATEGORIES.keys()),
                    width="medium"
                ),
                "in_network_coverage": st.column_config.TextColumn(
                    "In-Network Coverage",
                    width="large"
                ),
                "out_of_network_coverage": st.column_config.TextColumn(
                    "Out-of-Network Coverage", 
                    width="large"
                ),
                "coverage_type": st.column_config.SelectboxColumn(
                    "Coverage Type",
                    options=["copay", "coinsurance", "covered_100", "not_covered", "unknown"],
                    width="small"
                ),
                "spd_file": st.column_config.TextColumn(
                    "Source File",
                    width="medium"
                )
            },
            hide_index=True,
            use_container_width=True,
            num_rows="dynamic"
        )
        
        # Update session state with edits
        st.session_state.extracted_data = edited_df
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Export to Excel", use_container_width=True):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    edited_df.to_excel(writer, index=False, sheet_name='Benefits')
                    
                    # Add a summary sheet
                    summary_df = edited_df.groupby(['service_category', 'coverage_type']).size().reset_index(name='count')
                    summary_df.to_excel(writer, index=False, sheet_name='Summary')
                
                output.seek(0)
                st.download_button(
                    label="💾 Download Excel",
                    data=output,
                    file_name=f"spd_benefits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
        
        with col2:
            if st.button("🔄 Generate HRL", type="primary", use_container_width=True):
                with st.spinner("Generating HRL syntax..."):
                    hrl_syntax = generate_hrl_syntax(edited_df)
                    st.session_state.hrl_syntax = hrl_syntax
                    st.success("HRL syntax generated successfully!")
        
        with col3:
            if st.button("🗑️ Clear Data", use_container_width=True):
                st.session_state.extracted_data = pd.DataFrame()
                st.session_state.hrl_syntax = ""
                st.experimental_rerun()
    
    # Display HRL syntax
    if st.session_state.hrl_syntax:
        st.markdown("### 📝 Generated HRL Syntax")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.code(st.session_state.hrl_syntax, language="sql", line_numbers=True)
            
            st.download_button(
                label="📥 Download HRL File",
                data=st.session_state.hrl_syntax,
                file_name=f"benefits_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hrl",
                mime="text/plain",
                use_container_width=True
            )
        
        with col2:
            st.markdown("#### 🔍 HRL Preview")
            
            # Show rule count
            rule_count = st.session_state.hrl_syntax.count('IF (ServiceCategory')
            st.metric("Total Rules", rule_count)
            
            # Show coverage types found
            if not st.session_state.extracted_data.empty:
                coverage_types = st.session_state.extracted_data['coverage_type'].value_counts()
                st.markdown("**Coverage Types:**")
                for cov_type, count in coverage_types.items():
                    st.write(f"• {cov_type}: {count}")

if __name__ == "__main__":
    main()
